// 鉴权中间件：业务接口用访问令牌，管理接口接受「管理员登录态」或服务令牌
import type { MiddlewareHandler } from "hono";
import type { AppEnv } from "../env";
import { timingSafeEqualString } from "../lib/bytes";
import { fail } from "../lib/http";
import { verifyAccessToken } from "../lib/jwt";

function bearer(header: string | undefined): string | null {
  if (!header) return null;
  const matched = /^Bearer\s+(.+)$/i.exec(header.trim());
  return matched ? matched[1].trim() : null;
}

/**
 * 校验访问令牌并把身份写入上下文。
 * 除验签外还回查一次账号状态与角色：JWT 无法即时吊销，
 * 封禁和降权都必须在这里兜住，不能等令牌自然过期。
 */
export const requireUser: MiddlewareHandler<AppEnv> = async (c, next) => {
  const token = bearer(c.req.header("Authorization"));
  if (!token) return fail(c, 401, "unauthorized", "缺少访问令牌");

  const claims = await verifyAccessToken(
    c.env,
    token,
    Math.floor(Date.now() / 1000)
  );
  if (!claims) return fail(c, 401, "invalid_token", "访问令牌无效或已过期");

  const user = await c.env.DB.prepare(
    "SELECT id, status, role FROM users WHERE id = ?"
  )
    .bind(claims.sub)
    .first<{ id: string; status: string; role: string }>();
  if (!user) return fail(c, 401, "invalid_token", "账号不存在");
  if (user.status !== "active") {
    return fail(
      c,
      403,
      `account_${user.status}`,
      user.status === "banned" ? "账号已被封禁" : "账号已注销"
    );
  }

  c.set("userId", user.id);
  c.set("deviceId", claims.device_id ?? "");
  c.set("app", String(claims.aud ?? ""));
  // 角色取库里的实时值，而非令牌里的旧声明
  c.set("role", user.role);
  await next();
};

/**
 * 管理接口准入，两种身份都放行：
 *   1. 登录态里 role=admin 的访问令牌 —— 给管理页面用
 *   2. 静态 ADMIN_TOKEN —— 给脚本 / CI 用，也是引导出第一个管理员的入口
 */
export const requireAdmin: MiddlewareHandler<AppEnv> = async (c, next) => {
  const token = bearer(c.req.header("Authorization"));
  if (!token) return fail(c, 401, "unauthorized", "缺少管理凭据");

  // 先试服务令牌（恒定时间比较，避免被响应时间试探）
  if (c.env.ADMIN_TOKEN && timingSafeEqualString(token, c.env.ADMIN_TOKEN)) {
    c.set("userId", "");
    c.set("deviceId", "");
    c.set("app", "");
    c.set("role", "admin");
    return next();
  }

  const claims = await verifyAccessToken(
    c.env,
    token,
    Math.floor(Date.now() / 1000)
  );
  if (!claims) return fail(c, 401, "invalid_token", "管理凭据无效");

  const user = await c.env.DB.prepare(
    "SELECT id, status, role FROM users WHERE id = ?"
  )
    .bind(claims.sub)
    .first<{ id: string; status: string; role: string }>();
  if (!user) return fail(c, 401, "invalid_token", "账号不存在");
  if (user.status !== "active") {
    return fail(
      c,
      403,
      `account_${user.status}`,
      user.status === "banned" ? "账号已被封禁" : "账号已注销"
    );
  }
  // 同样以库里的实时角色为准
  if (user.role !== "admin") {
    return fail(c, 403, "forbidden", "需要管理员权限");
  }

  c.set("userId", user.id);
  c.set("deviceId", claims.device_id ?? "");
  c.set("app", String(claims.aud ?? ""));
  c.set("role", "admin");
  await next();
};
