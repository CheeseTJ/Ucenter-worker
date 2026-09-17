// 鉴权中间件：业务接口用访问令牌，管理接口用服务令牌
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
 * 除验签外还回查一次账号状态：JWT 无法即时吊销，封禁必须在这里兜住。
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

  const user = await c.env.DB.prepare("SELECT id, status FROM users WHERE id = ?")
    .bind(claims.sub)
    .first<{ id: string; status: string }>();
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
  await next();
};

export const requireAdmin: MiddlewareHandler<AppEnv> = async (c, next) => {
  const token = bearer(c.req.header("Authorization"));
  if (
    !token ||
    !c.env.ADMIN_TOKEN ||
    !timingSafeEqualString(token, c.env.ADMIN_TOKEN)
  ) {
    return fail(c, 401, "unauthorized", "管理令牌无效");
  }
  await next();
};
