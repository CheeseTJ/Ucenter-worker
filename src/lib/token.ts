// 令牌生成与哈希：刷新令牌 / 邀请码的明文只发给客户端，库里只存不可逆哈希
import { randomBytes, toBase64Url, utf8 } from "./bytes";

export async function sha256Base64Url(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", utf8(input));
  return toBase64Url(new Uint8Array(digest));
}

/** 32 字节随机，约 256 bit 熵，不可枚举 */
export function newRefreshToken(): string {
  return toBase64Url(randomBytes(32));
}

/** 邀请码：9 字节 → 12 个 base64url 字符，够安全也方便手抄 */
export function newInviteCode(): string {
  return toBase64Url(randomBytes(9));
}
