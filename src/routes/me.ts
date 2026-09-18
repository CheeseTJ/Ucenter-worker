// 自助接口：当前用户、改密、设备管理
import { Hono } from "hono";
import type { AppEnv } from "../env";
import { pbkdf2Iterations } from "../lib/config";
import { fail, readJson, readPassword } from "../lib/http";
import { hashPassword, verifyPassword } from "../lib/password";
import { issueTokenPair, revokeAllForUser, revokeDevice } from "../lib/sessions";
import { requireUser } from "../middleware/auth";

export const meRoute = new Hono<AppEnv>();

meRoute.use("*", requireUser);

interface DeviceRow {
  id: string;
  name: string;
  platform: string;
  last_seen: number;
  created_at: number;
  revoked_at: number | null;
}

meRoute.get("/", async (c) => {
  const user = await c.env.DB.prepare(
    "SELECT id, email, status, role, created_at FROM users WHERE id = ?"
  )
    .bind(c.get("userId"))
    .first();
  if (!user) return fail(c, 404, "not_found", "账号不存在");

  return c.json({
    user,
    device_id: c.get("deviceId"),
    app: c.get("app"),
    role: c.get("role"),
  });
});

meRoute.post("/password", async (c) => {
  const body = await readJson<Record<string, unknown>>(c);
  if (!body) return fail(c, 400, "invalid_body", "请求体必须是 JSON");

  const oldPassword =
    typeof body.old_password === "string" ? body.old_password : "";
  const newPassword = readPassword(body.new_password);
  if (!oldPassword) return fail(c, 400, "invalid_password", "请输入当前密码");
  if (!newPassword) {
    return fail(c, 400, "invalid_password", "新密码长度需为 8-128 位");
  }

  const userId = c.get("userId");
  const row = await c.env.DB.prepare(
    "SELECT email, role, password_hash FROM users WHERE id = ?"
  )
    .bind(userId)
    .first<{ email: string; role: string; password_hash: string }>();
  if (!row) return fail(c, 404, "not_found", "账号不存在");

  const oldOk = await verifyPassword(
    oldPassword,
    row.password_hash,
    c.env.PASSWORD_PEPPER
  );
  if (!oldOk) return fail(c, 401, "invalid_password", "当前密码错误");

  const at = Math.floor(Date.now() / 1000);
  const nextHash = await hashPassword(
    newPassword,
    pbkdf2Iterations(c.env),
    c.env.PASSWORD_PEPPER
  );
  await c.env.DB.prepare("UPDATE users SET password_hash = ? WHERE id = ?")
    .bind(nextHash, userId)
    .run();

  // 改密后吊销所有设备：若账号是被盗后改密，小偷手里的令牌必须立即失效
  await revokeAllForUser(c.env, userId, at);

  // 当前设备重新启用并换发新令牌，本人不必重新登录
  const deviceId = c.get("deviceId");
  await c.env.DB.prepare("UPDATE devices SET revoked_at = NULL WHERE id = ?")
    .bind(deviceId)
    .run();

  const pair = await issueTokenPair(c.env, new URL(c.req.url).origin, {
    userId,
    email: row.email,
    role: row.role,
    deviceId,
    app: c.get("app"),
    now: at,
  });
  return c.json({ ok: true, ...pair });
});

meRoute.get("/devices", async (c) => {
  const rows = await c.env.DB.prepare(
    `SELECT id, name, platform, last_seen, created_at, revoked_at
     FROM devices WHERE user_id = ? ORDER BY last_seen DESC`
  )
    .bind(c.get("userId"))
    .all<DeviceRow>();

  const currentDeviceId = c.get("deviceId");
  return c.json({
    devices: rows.results.map((device) => ({
      ...device,
      current: device.id === currentDeviceId,
    })),
  });
});

meRoute.delete("/devices/:id", async (c) => {
  const deviceId = c.req.param("id");
  const device = await c.env.DB.prepare(
    "SELECT id, user_id FROM devices WHERE id = ?"
  )
    .bind(deviceId)
    .first<{ id: string; user_id: string }>();

  // 不区分「不存在」与「不属于当前用户」，避免探测他人设备 ID
  if (!device || device.user_id !== c.get("userId")) {
    return fail(c, 404, "not_found", "设备不存在");
  }

  await revokeDevice(c.env, deviceId, Math.floor(Date.now() / 1000));
  return c.json({ ok: true, current: deviceId === c.get("deviceId") });
});
