// 认证接口：注册（需邀请码）/ 登录 / 刷新 / 登出
import { Hono } from "hono";
import type { Context } from "hono";
import type { AppEnv, Env } from "../env";
import { randomId } from "../lib/bytes";
import { isAppAllowed, pbkdf2Iterations, requestIp } from "../lib/config";
import {
  fail,
  normalizeEmail,
  readDeviceInfo,
  readJson,
  readPassword,
} from "../lib/http";
import {
  fakeVerifyPassword,
  hashPassword,
  parseIterations,
  verifyPassword,
} from "../lib/password";
import {
  issueTokenPair,
  resolveDevice,
  revokeByRefreshToken,
  rotateRefreshToken,
} from "../lib/sessions";
import { sha256Base64Url } from "../lib/token";
import { notify, table, row as row2, wrap, esc } from "../lib/notify";

export const authRoute = new Hono<AppEnv>();

interface UserRow {
  id: string;
  email: string;
  password_hash: string;
  status: string;
  role: string;
}

// 账号不存在与密码错误返回同一句提示，避免被用来枚举已注册邮箱
const INVALID_CREDENTIALS = "邮箱或密码错误";

function now(): number {
  return Math.floor(Date.now() / 1000);
}

function issuerOf(c: Context<AppEnv>): string {
  return new URL(c.req.url).origin;
}

async function underLimit(c: Context<AppEnv>, key: string): Promise<boolean> {
  const { success } = await c.env.RL_AUTH.limit({ key });
  return success;
}

/** 暴力破解告警阈值：同一邮箱在窗口期内失败这么多次就发信。 */
const BRUTE_FORCE_THRESHOLD = 5;
/** 统计窗口（秒）。15 分钟内 5 次失败大概率不是手抖。 */
const BRUTE_FORCE_WINDOW = 15 * 60;

async function recordAttempt(
  env: Env,
  email: string,
  ip: string,
  ok: boolean,
  at: number
): Promise<void> {
  try {
    await env.DB.prepare(
      "INSERT INTO login_attempts (email, ip, ok, at) VALUES (?, ?, ?, ?)"
    )
      .bind(email, ip, ok ? 1 : 0, at)
      .run();
  } catch (error) {
    // 审计只是旁路：写不进去（例如库写满）也不该让登录本身失败
    console.error("[user-center] 写入登录审计失败", error);
  }

  // 只在失败时检查：成功登录意味着已经拿到正确口令，不需要告警
  if (ok) return;

  try {
    const since = at - BRUTE_FORCE_WINDOW;
    const row = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM login_attempts WHERE email = ? AND ok = 0 AND at >= ?"
    )
      .bind(email, since)
      .first<{ n: number }>();

    const failures = row?.n ?? 0;
    // 只在「刚好达到阈值」时发一次。否则第 6、7、8 次失败都会再发一封，
    // 攻击者持续尝试就会把邮箱刷爆 —— 告警疲劳比没有告警更糟。
    if (failures !== BRUTE_FORCE_THRESHOLD) return;

    await notify(
      env,
      `【Ucenter】检测到暴力破解尝试：${email}`,
      wrap(
        "登录失败次数异常",
        `<p style="font-size:13px;color:#374151;margin:0 0 12px">` +
          `账号 <strong>${esc(email)}</strong> 在 15 分钟内连续登录失败 ` +
          `<strong>${failures}</strong> 次，疑似暴力破解。</p>` +
          table(
            row2("最近来源 IP", ip) +
              row2("首次统计起", new Date(since * 1000).toISOString().slice(0, 19).replace("T", " ") + " UTC"),
          ) +
          `<p style="font-size:12px;color:#9ca3af;margin:14px 0 0">` +
          `如果这是你自己在试密码，可以忽略；否则建议检查该账号并考虑改密。</p>`,
      ),
    );
  } catch (error) {
    // 统计失败不能影响登录流程
    console.error("[user-center] 暴力破解检测失败", error);
  }
}

authRoute.post("/register", async (c) => {
  const body = await readJson<Record<string, unknown>>(c);
  if (!body) return fail(c, 400, "invalid_body", "请求体必须是 JSON");

  const at = now();
  const email = normalizeEmail(body.email);
  const password = readPassword(body.password);
  const app = typeof body.app === "string" ? body.app.trim() : "";
  const inviteCode =
    typeof body.invite_code === "string" ? body.invite_code.trim() : "";

  if (!email) return fail(c, 400, "invalid_email", "邮箱格式不正确");
  if (!password) return fail(c, 400, "invalid_password", "密码长度需为 8-128 位");
  if (!app) return fail(c, 400, "invalid_app", "缺少 app 参数");
  if (!isAppAllowed(c.env, app)) {
    return fail(c, 400, "unknown_app", `应用 ${app} 未在用户中心注册`);
  }
  if (!inviteCode) return fail(c, 400, "invite_required", "缺少邀请码");

  const ip = requestIp(c.req.raw.headers);
  if (!(await underLimit(c, `register:${ip}`))) {
    return fail(c, 429, "rate_limited", "尝试过于频繁，请稍后再试");
  }

  // 条件更新即原子占位：并发注册时只有一个人能抢到最后一个名额
  const consumed = await c.env.DB.prepare(
    `UPDATE invites SET uses = uses + 1
     WHERE code_hash = ?
       AND (expires_at IS NULL OR expires_at > ?)
       AND (max_uses = 0 OR uses < max_uses)`
  )
    .bind(await sha256Base64Url(inviteCode), at)
    .run();
  if (!consumed.meta.changes) {
    return fail(c, 403, "invalid_invite", "邀请码无效或已用尽");
  }

  const userId = randomId("u");
  const passwordHash = await hashPassword(
    password,
    pbkdf2Iterations(c.env),
    c.env.PASSWORD_PEPPER
  );

  // 首个注册的账号自动成为管理员，避免「没有管理员就没法引导」的死结；
  // 之后再注册的一律是普通用户，提升/降级走 /v1/admin/users/:id
  const count = await c.env.DB.prepare("SELECT COUNT(*) AS n FROM users").first<{ n: number }>();
  const role = (count?.n ?? 0) === 0 ? "admin" : "user";

  try {
    await c.env.DB.prepare(
      "INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, ?, ?)"
    )
      .bind(userId, email, passwordHash, role)
      .run();
  } catch {
    // email 上有 UNIQUE 约束；能走到这里说明并发注册了同一邮箱
    return fail(c, 409, "email_taken", "该邮箱已注册");
  }

  const device = readDeviceInfo(body);
  const deviceId = await resolveDevice(
    c.env,
    userId,
    device.deviceId,
    device.deviceName,
    device.platform,
    at
  );
  const pair = await issueTokenPair(c.env, issuerOf(c), {
    userId,
    email,
    role,
    deviceId,
    app,
    now: at,
  });

  await recordAttempt(c.env, email, ip, true, at);
  return c.json({ user: { id: userId, email }, ...pair }, 201);
});

authRoute.post("/login", async (c) => {
  const body = await readJson<Record<string, unknown>>(c);
  if (!body) return fail(c, 400, "invalid_body", "请求体必须是 JSON");

  const at = now();
  const email = normalizeEmail(body.email);
  const password = typeof body.password === "string" ? body.password : "";
  const app = typeof body.app === "string" ? body.app.trim() : "";

  if (!email || !password) {
    return fail(c, 400, "invalid_credentials", "请输入邮箱和密码");
  }
  if (!isAppAllowed(c.env, app)) {
    return fail(c, 400, "unknown_app", `应用 ${app} 未在用户中心注册`);
  }

  const ip = requestIp(c.req.raw.headers);
  if (!(await underLimit(c, `login:${email}`))) {
    return fail(c, 429, "rate_limited", "尝试过于频繁，请稍后再试");
  }

  const iterations = pbkdf2Iterations(c.env);
  const user = await c.env.DB.prepare(
    "SELECT id, email, password_hash, status, role FROM users WHERE email = ?"
  )
    .bind(email)
    .first<UserRow>();

  if (!user) {
    // 账号不存在也要付出等价的哈希开销，否则响应时间会泄露邮箱是否注册过
    await fakeVerifyPassword(iterations, c.env.PASSWORD_PEPPER);
    await recordAttempt(c.env, email, ip, false, at);
    return fail(c, 401, "invalid_credentials", INVALID_CREDENTIALS);
  }

  const passwordOk = await verifyPassword(
    password,
    user.password_hash,
    c.env.PASSWORD_PEPPER
  );
  if (!passwordOk) {
    await recordAttempt(c.env, email, ip, false, at);
    return fail(c, 401, "invalid_credentials", INVALID_CREDENTIALS);
  }

  if (user.status !== "active") {
    await recordAttempt(c.env, email, ip, false, at);
    return fail(
      c,
      403,
      `account_${user.status}`,
      user.status === "banned" ? "账号已被封禁" : "账号已注销"
    );
  }

  // 迭代数上调后，老哈希在本人登录成功这一刻顺带升级，无需强制所有人改密码
  if (parseIterations(user.password_hash) !== iterations) {
    const upgraded = await hashPassword(
      password,
      iterations,
      c.env.PASSWORD_PEPPER
    );
    await c.env.DB.prepare("UPDATE users SET password_hash = ? WHERE id = ?")
      .bind(upgraded, user.id)
      .run();
  }

  const device = readDeviceInfo(body);
  const deviceId = await resolveDevice(
    c.env,
    user.id,
    device.deviceId,
    device.deviceName,
    device.platform,
    at
  );
  const pair = await issueTokenPair(c.env, issuerOf(c), {
    userId: user.id,
    email: user.email,
    role: user.role,
    deviceId,
    app,
    now: at,
  });

  await recordAttempt(c.env, email, ip, true, at);
  return c.json({ user: { id: user.id, email: user.email }, ...pair });
});

authRoute.post("/refresh", async (c) => {
  const body = await readJson<Record<string, unknown>>(c);
  if (!body) return fail(c, 400, "invalid_body", "请求体必须是 JSON");

  const refreshToken =
    typeof body.refresh_token === "string" ? body.refresh_token : "";
  const app = typeof body.app === "string" ? body.app.trim() : "";
  if (!refreshToken) {
    return fail(c, 400, "invalid_refresh_token", "缺少 refresh_token");
  }
  if (!isAppAllowed(c.env, app)) {
    return fail(c, 400, "unknown_app", `应用 ${app} 未在用户中心注册`);
  }

  const result = await rotateRefreshToken(c.env, issuerOf(c), {
    refreshToken,
    app,
    now: now(),
  });
  if (result.ok) return c.json(result.pair);

  switch (result.reason) {
    case "expired":
      return fail(c, 401, "refresh_token_expired", "登录已过期，请重新登录");
    case "device_revoked":
      return fail(c, 401, "device_revoked", "该设备已被吊销，请重新登录");
    case "user_inactive":
      return fail(c, 403, "account_inactive", "账号不可用");
    default:
      // not_found / reused：一律重新登录
      return fail(c, 401, "invalid_refresh_token", "刷新令牌无效，请重新登录");
  }
});

authRoute.post("/logout", async (c) => {
  const body = await readJson<Record<string, unknown>>(c);
  const refreshToken =
    body && typeof body.refresh_token === "string" ? body.refresh_token : "";
  if (!refreshToken) {
    return fail(c, 400, "invalid_refresh_token", "缺少 refresh_token");
  }

  await revokeByRefreshToken(c.env, refreshToken, now());
  return c.json({ ok: true });
});
