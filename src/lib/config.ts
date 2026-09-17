// 配置读取：把字符串型的环境变量收敛成带默认值的类型化取值
import type { Env } from "../env";

export function accessTtl(env: Env): number {
  return Number(env.ACCESS_TOKEN_TTL) || 900;
}

export function refreshTtl(env: Env): number {
  return Number(env.REFRESH_TOKEN_TTL) || 90 * 24 * 3600;
}

export function pbkdf2Iterations(env: Env): number {
  return Number(env.PBKDF2_ITERATIONS) || 100_000;
}

export function allowedApps(env: Env): string[] {
  return (env.APPS || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

export function isAppAllowed(env: Env, app: string): boolean {
  return allowedApps(env).includes(app);
}

export function requestIp(headers: Headers): string {
  return headers.get("cf-connecting-ip") || "";
}
