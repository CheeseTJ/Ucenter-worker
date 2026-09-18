// 会话：设备注册、令牌签发与轮换、吊销
//
// 刷新令牌采用「旋转 + 复用检测」：每次刷新都换发新令牌，
// 旧令牌若被再次使用，说明它已泄露（正常客户端不会重复使用），
// 此时吊销整条旋转链，把攻击者和本人一起踢下线。
import type { Env } from "../env";
import { randomId } from "./bytes";
import { accessTtl, refreshTtl } from "./config";
import { signAccessToken } from "./jwt";
import { newRefreshToken, sha256Base64Url } from "./token";

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  token_type: "Bearer";
  device_id: string;
}

export type RotateFailure =
  | "not_found"
  | "reused"
  | "expired"
  | "device_revoked"
  | "user_inactive";

interface RefreshRow {
  token_hash: string;
  user_id: string;
  device_id: string;
  family_id: string;
  expires_at: number;
  revoked_at: number | null;
}

/**
 * 解析客户端上报的设备：
 * 客户端首次登录后应保存返回的 device_id，之后一直带上，这样「我的设备」才是稳定的。
 * 未上报或不属于该用户时新建一台。
 */
export async function resolveDevice(
  env: Env,
  userId: string,
  providedId: string | undefined,
  name: string,
  platform: string,
  now: number
): Promise<string> {
  if (providedId) {
    const existing = await env.DB.prepare(
      "SELECT id, user_id, revoked_at FROM devices WHERE id = ?"
    )
      .bind(providedId)
      .first<{ id: string; user_id: string; revoked_at: number | null }>();

    if (existing && existing.user_id === userId && existing.revoked_at === null) {
      await env.DB.prepare("UPDATE devices SET last_seen = ? WHERE id = ?")
        .bind(now, providedId)
        .run();
      return providedId;
    }
  }

  const deviceId = randomId("dev");
  await env.DB.prepare(
    "INSERT INTO devices (id, user_id, name, platform, last_seen) VALUES (?, ?, ?, ?, ?)"
  )
    .bind(deviceId, userId, name, platform, now)
    .run();
  return deviceId;
}

/** 登录 / 注册成功后签发一对新令牌 */
export async function issueTokenPair(
  env: Env,
  issuer: string,
  params: {
    userId: string;
    email: string;
    role: string;
    deviceId: string;
    app: string;
    now: number;
  }
): Promise<TokenPair> {
  const { userId, email, role, deviceId, app, now } = params;
  const ttl = accessTtl(env);
  const refresh = newRefreshToken();

  const accessToken = await signAccessToken(
    env,
    issuer,
    { userId, email, role, app, deviceId, jti: randomId("jti") },
    ttl,
    now
  );

  await env.DB.prepare(
    "INSERT INTO refresh_tokens (token_hash, user_id, device_id, family_id, expires_at) VALUES (?, ?, ?, ?, ?)"
  )
    .bind(
      await sha256Base64Url(refresh),
      userId,
      deviceId,
      randomId("fam"),
      now + refreshTtl(env)
    )
    .run();

  return {
    access_token: accessToken,
    refresh_token: refresh,
    expires_in: ttl,
    token_type: "Bearer",
    device_id: deviceId,
  };
}

/** 校验并旋转刷新令牌 */
export async function rotateRefreshToken(
  env: Env,
  issuer: string,
  params: { refreshToken: string; app: string; now: number }
): Promise<{ ok: true; pair: TokenPair } | { ok: false; reason: RotateFailure }> {
  const { refreshToken, app, now } = params;
  const tokenHash = await sha256Base64Url(refreshToken);

  const row = await env.DB.prepare(
    "SELECT token_hash, user_id, device_id, family_id, expires_at, revoked_at FROM refresh_tokens WHERE token_hash = ?"
  )
    .bind(tokenHash)
    .first<RefreshRow>();

  if (!row) return { ok: false, reason: "not_found" };

  if (row.revoked_at !== null) {
    // 已被轮换或吊销的令牌又被使用 → 判定为泄露，连同整条链一起作废
    await revokeFamily(env, row.family_id, now);
    return { ok: false, reason: "reused" };
  }
  if (row.expires_at <= now) return { ok: false, reason: "expired" };

  const device = await env.DB.prepare(
    "SELECT id, revoked_at FROM devices WHERE id = ?"
  )
    .bind(row.device_id)
    .first<{ id: string; revoked_at: number | null }>();
  if (!device || device.revoked_at !== null) {
    return { ok: false, reason: "device_revoked" };
  }

  const user = await env.DB.prepare(
    "SELECT id, email, role, status FROM users WHERE id = ?"
  )
    .bind(row.user_id)
    .first<{ id: string; email: string; role: string; status: string }>();
  if (!user || user.status !== "active") {
    return { ok: false, reason: "user_inactive" };
  }

  const ttl = accessTtl(env);
  const next = newRefreshToken();
  const nextHash = await sha256Base64Url(next);

  const accessToken = await signAccessToken(
    env,
    issuer,
    { userId: row.user_id, email: user.email, role: user.role, app, deviceId: row.device_id, jti: randomId("jti") },
    ttl,
    now
  );

  // 新令牌入库与旧令牌作废放在同一个 batch 里，避免中途失败出现两个可用令牌
  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO refresh_tokens (token_hash, user_id, device_id, family_id, expires_at) VALUES (?, ?, ?, ?, ?)"
    ).bind(nextHash, row.user_id, row.device_id, row.family_id, now + refreshTtl(env)),
    env.DB.prepare(
      "UPDATE refresh_tokens SET revoked_at = ?, replaced_by = ? WHERE token_hash = ?"
    ).bind(now, nextHash, tokenHash),
    env.DB.prepare("UPDATE devices SET last_seen = ? WHERE id = ?").bind(
      now,
      row.device_id
    ),
  ]);

  return {
    ok: true,
    pair: {
      access_token: accessToken,
      refresh_token: next,
      expires_in: ttl,
      token_type: "Bearer",
      device_id: row.device_id,
    },
  };
}

/** 按令牌哈希定位并吊销整条旋转链（登出用） */
export async function revokeByRefreshToken(
  env: Env,
  refreshToken: string,
  now: number
): Promise<void> {
  const tokenHash = await sha256Base64Url(refreshToken);
  const row = await env.DB.prepare(
    "SELECT family_id FROM refresh_tokens WHERE token_hash = ?"
  )
    .bind(tokenHash)
    .first<{ family_id: string }>();
  if (row) await revokeFamily(env, row.family_id, now);
}

export async function revokeFamily(
  env: Env,
  familyId: string,
  now: number
): Promise<void> {
  await env.DB.prepare(
    "UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL"
  )
    .bind(now, familyId)
    .run();
}

/** 吊销某台设备及其名下所有令牌 */
export async function revokeDevice(
  env: Env,
  deviceId: string,
  now: number
): Promise<void> {
  await env.DB.batch([
    env.DB.prepare(
      "UPDATE devices SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL"
    ).bind(now, deviceId),
    env.DB.prepare(
      "UPDATE refresh_tokens SET revoked_at = ? WHERE device_id = ? AND revoked_at IS NULL"
    ).bind(now, deviceId),
  ]);
}

/** 吊销该用户全部设备（改密、封禁、管理员强制下线用） */
export async function revokeAllForUser(
  env: Env,
  userId: string,
  now: number
): Promise<void> {
  await env.DB.batch([
    env.DB.prepare(
      "UPDATE devices SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL"
    ).bind(now, userId),
    env.DB.prepare(
      "UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL"
    ).bind(now, userId),
  ]);
}
