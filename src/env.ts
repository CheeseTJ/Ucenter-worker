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
  /** 允许的跨域来源，逗号分隔；留空表示允许所有来源 */
  ALLOWED_ORIGINS: string;
}

export interface Variables {
  userId: string;
  deviceId: string;
  app: string;
}

export type AppEnv = { Bindings: Env; Variables: Variables };
