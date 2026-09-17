// HTTP 层公共工具：统一错误响应、JSON 解析、字段校验
import type { Context } from "hono";
import type { AppEnv } from "../env";

/** fail() 允许的状态码，收敛取值避免误用 */
export type FailStatus = 400 | 401 | 403 | 404 | 409 | 429 | 500;

export function fail(
  c: Context<AppEnv>,
  status: FailStatus,
  code: string,
  message: string
) {
  return c.json({ code, message }, status);
}

export async function readJson<T>(c: Context<AppEnv>): Promise<T | null> {
  try {
    return (await c.req.json()) as T;
  } catch {
    return null;
  }
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** 邮箱规范化：去空格、转小写（避免 A@x.com 与 a@x.com 被当成两个账号） */
export function normalizeEmail(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const email = raw.trim().toLowerCase();
  if (email.length < 3 || email.length > 254 || !EMAIL_RE.test(email)) return null;
  return email;
}

export function readPassword(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  if (raw.length < 8 || raw.length > 128) return null;
  return raw;
}

/** 客户端上报的设备信息，用于在「我的设备」里展示 */
export interface DeviceInfo {
  deviceId?: string;
  deviceName: string;
  platform: string;
}

export function readDeviceInfo(body: Record<string, unknown>): DeviceInfo {
  const str = (v: unknown, max: number) =>
    typeof v === "string" ? v.trim().slice(0, max) : "";
  return {
    deviceId: str(body.device_id, 64) || undefined,
    deviceName: str(body.device_name, 64) || "未命名设备",
    platform: str(body.platform, 32),
  };
}
