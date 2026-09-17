// 管理接口：邀请码、用户封禁、强制下线（仅凭 ADMIN_TOKEN 访问）
import { Hono } from "hono";
import type { AppEnv } from "../env";
import { fail, readJson } from "../lib/http";
import { revokeAllForUser } from "../lib/sessions";
import { newInviteCode, sha256Base64Url } from "../lib/token";
import { requireAdmin } from "../middleware/auth";

export const adminRoute = new Hono<AppEnv>();

adminRoute.use("*", requireAdmin);

const MAX_PAGE_SIZE = 200;

adminRoute.post("/invites", async (c) => {
  const body = (await readJson<Record<string, unknown>>(c)) ?? {};

  const note = typeof body.note === "string" ? body.note.trim().slice(0, 128) : "";
  const requestedUses = Number(body.max_uses);
  // max_uses 传 0 或负数视为不限次数
  const maxUses =
    Number.isInteger(requestedUses) && requestedUses > 0 ? requestedUses : 1;
  const days = Number(body.expires_in_days);
  const expiresAt =
    Number.isFinite(days) && days > 0
      ? Math.floor(Date.now() / 1000) + Math.round(days * 86400)
      : null;

  const code = newInviteCode();
  await c.env.DB.prepare(
    "INSERT INTO invites (code_hash, note, max_uses, expires_at) VALUES (?, ?, ?, ?)"
  )
    .bind(await sha256Base64Url(code), note, maxUses, expiresAt)
    .run();

  // 明文邀请码只在这里返回一次，库里只有哈希，之后无法再查出来
  return c.json({ code, note, max_uses: maxUses, expires_at: expiresAt }, 201);
});

adminRoute.get("/invites", async (c) => {
  const rows = await c.env.DB.prepare(
    `SELECT code_hash AS id, note, max_uses, uses, expires_at, created_at
     FROM invites ORDER BY created_at DESC LIMIT 200`
  ).all();
  return c.json({ invites: rows.results });
});

adminRoute.get("/users", async (c) => {
  const limit = Math.min(
    Math.max(Number(c.req.query("limit")) || 50, 1),
    MAX_PAGE_SIZE
  );
  const offset = Math.max(Number(c.req.query("offset")) || 0, 0);

  const rows = await c.env.DB.prepare(
    `SELECT id, email, status, created_at FROM users
     ORDER BY created_at DESC LIMIT ? OFFSET ?`
  )
    .bind(limit, offset)
    .all();
  const total = await c.env.DB.prepare("SELECT COUNT(*) AS count FROM users").first<{
    count: number;
  }>();

  return c.json({ users: rows.results, total: total?.count ?? 0, limit, offset });
});

adminRoute.patch("/users/:id", async (c) => {
  const body = await readJson<Record<string, unknown>>(c);
  if (!body || typeof body.status !== "string") {
    return fail(c, 400, "invalid_status", "缺少 status 参数");
  }
  const status = body.status;
  if (status !== "active" && status !== "banned") {
    return fail(c, 400, "invalid_status", "status 只能是 active 或 banned");
  }

  const userId = c.req.param("id");
  const updated = await c.env.DB.prepare(
    "UPDATE users SET status = ? WHERE id = ?"
  )
    .bind(status, userId)
    .run();
  if (!updated.meta.changes) return fail(c, 404, "not_found", "用户不存在");

  // 封禁必须同时吊销令牌，否则封禁要等访问令牌过期才真正生效
  if (status === "banned") {
    await revokeAllForUser(c.env, userId, Math.floor(Date.now() / 1000));
  }
  return c.json({ ok: true, id: userId, status });
});

adminRoute.post("/users/:id/revoke", async (c) => {
  const userId = c.req.param("id");
  const user = await c.env.DB.prepare("SELECT id FROM users WHERE id = ?")
    .bind(userId)
    .first<{ id: string }>();
  if (!user) return fail(c, 404, "not_found", "用户不存在");

  await revokeAllForUser(c.env, userId, Math.floor(Date.now() / 1000));
  return c.json({ ok: true, id: userId });
});
