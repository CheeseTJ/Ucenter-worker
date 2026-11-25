// 绑定与请求上下文类型
export interface RateLimiter {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

export interface Env {
  DB: D1Database;
  /** 认证接口限流（wrangler.jsonc 的 ratelimits 绑定） */
  RL_AUTH: RateLimiter;
  /** Ed25519 私钥 JWK（含 x 与 d），公钥由此推导 */
  JWT_PRIVATE_JWK: string;
  /** 口令哈希的 pepper，可选但强烈建议配置 */
  PASSWORD_PEPPER?: string;
  /** /v1/admin/* 的管理令牌 */
  ADMIN_TOKEN: string;
  /** 允许接入的应用白名单，逗号分隔 */
  APPS: string;
  /** 访问令牌有效期（秒） */
  ACCESS_TOKEN_TTL: string;
  /** 刷新令牌有效期（秒） */
  REFRESH_TOKEN_TTL: string;
  /** 口令哈希迭代次数 */
  PBKDF2_ITERATIONS: string;
  /** 登录审计记录保留天数，默认 7 */
  LOGIN_ATTEMPT_RETENTION_DAYS?: string;
  /** 允许的跨域来源，逗号分隔；留空表示允许所有来源 */
  ALLOWED_ORIGINS: string;

  // ---- 邮件通知（可选）----
  // Worker 运行时没有裸 TCP，无法直连 SMTP，只能通过 HTTP 网关转发。
  // 三项全配齐才生效，缺任一项则静默跳过通知，不影响任何接口。

  /** 邮件网关地址，如 https://mail.june-t.top/internal/mail/send */
  MAIL_API_URL?: string;
  /** 网关 Bearer 令牌 */
  MAIL_API_TOKEN?: string;
  /** 收件人，逗号分隔 */
  MAIL_TO?: string;
}

export interface Variables {
  userId: string;
  deviceId: string;
  app: string;
  /** 当前请求者的角色：user | admin */
  role: string;
}

export type AppEnv = { Bindings: Env; Variables: Variables };
