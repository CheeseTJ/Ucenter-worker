// 管理接口：概览、用户、邀请码、强制下线
// 准入由 requireAdmin 负责：接受 admin 角色的登录令牌，或静态 ADMIN_TOKEN
import { Hono } from "hono";
import type { AppEnv } from "../env";
import { fail, readJson } from "../lib/http";
import { revokeAllForUser } from "../lib/sessions";
import { newInviteCode, sha256Base64Url } from "../lib/token";
import { requireAdmin } from "../middleware/auth";

export const adminRoute = new Hono<AppEnv>();

adminRoute.use("*", requireAdmin);

const MAX_PAGE_SIZE = 200;

// 账号可选状态。deleted 是软删除：账号立即不能登录，但业务数据保留
const ALLOWED_STATUS = ["active", "banned", "deleted"] as const;
type UserStatus = (typeof ALLOWED_STATUS)[number];

/** 概览统计：管理页面首屏用，避免前端拉全量列表自己算 */
adminRoute.get("/overview", async (c) => {
  const stats = await c.env.DB.prepare(
    `SELECT
       (SELECT COUNT(*) FROM users)                                  AS users,
       (SELECT COUNT(*) FROM users WHERE status = 'banned')           AS banned,
       (SELECT COUNT(*) FROM users WHERE status = 'deleted')          AS deleted,
       (SELECT COUNT(*) FROM devices WHERE revoked_at IS NULL)        AS devices,
       (SELECT COUNT(*) FROM invites
          WHERE (expires_at IS NULL OR expires_at > unixepoch())
            AND (max_uses = 0 OR uses < max_uses))                    AS invites`
  ).first();

  const attempts = await c.env.DB.prepare(
    `SELECT email, ip, ok, at FROM login_attempts ORDER BY at DESC LIMIT 12`
  ).all();

  return c.json({ stats, attempts: attempts.results });
});

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
    `SELECT u.id, u.email, u.status, u.role, u.created_at,
            (SELECT COUNT(*) FROM devices d
               WHERE d.user_id = u.id AND d.revoked_at IS NULL)        AS devices,
            (SELECT MAX(d.last_seen) FROM devices d
               WHERE d.user_id = u.id)                                  AS last_seen
     FROM users u
     ORDER BY u.created_at DESC LIMIT ? OFFSET ?`
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
  const status = body.status as UserStatus;
  if (!ALLOWED_STATUS.includes(status)) {
    return fail(c, 400, "invalid_status", `status 只能是 ${ALLOWED_STATUS.join(" / ")}`);
  }

  const userId = c.req.param("id");
  // 自己把自己封禁/注销会直接锁死管理入口，服务端必须拦住（前端禁用只是提示）
  if (userId === c.get("userId")) {
    return fail(c, 400, "self_forbidden", "不能对自己执行该操作");
  }

  const now = Math.floor(Date.now() / 1000);
  // 注销时记录 deleted_at（已注销过则保留首次时间），恢复时清空
  const updated = await c.env.DB.prepare(
    `UPDATE users
     SET status = ?,
         deleted_at = CASE WHEN ? = 'deleted' THEN COALESCE(deleted_at, ?) ELSE NULL END
     WHERE id = ?`
  )
    .bind(status, status, now, userId)
    .run();
  if (!updated.meta.changes) return fail(c, 404, "not_found", "用户不存在");

  // 封禁与注销都必须同时吊销令牌，否则要等访问令牌过期才真正生效
  if (status !== "active") {
    await revokeAllForUser(c.env, userId, now);
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
