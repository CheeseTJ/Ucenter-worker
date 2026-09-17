// 口令哈希：PBKDF2-SHA256 + 每人独立 salt + 全局 pepper
//
// 存储格式（自描述，便于将来无痛提升迭代次数）：
//   pbkdf2-sha256$<迭代次数>$<salt(base64url)>$<派生结果(base64url)>
//
// 不存明文，也不存可逆密文：校验靠「用同样的参数重算一遍再比对」。
import { randomBytes, fromBase64Url, toBase64Url, timingSafeEqual, utf8 } from "./bytes";

const ALGORITHM = "pbkdf2-sha256";
const KEY_BITS = 256;
const SALT_BYTES = 16;

async function derive(
  password: string,
  salt: Uint8Array,
  iterations: number,
  pepper?: string
): Promise<Uint8Array> {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    utf8(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    baseKey,
    KEY_BITS
  );
  const derived = new Uint8Array(bits);

  // pepper 不进数据库：即使 D1 被整体拖走，没有它也无法离线爆破
  if (!pepper) return derived;
  const pepperKey = await crypto.subtle.importKey(
    "raw",
    utf8(pepper),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", pepperKey, derived));
}

export async function hashPassword(
  password: string,
  iterations: number,
  pepper?: string
): Promise<string> {
  const salt = randomBytes(SALT_BYTES);
  const hash = await derive(password, salt, iterations, pepper);
  return `${ALGORITHM}$${iterations}$${toBase64Url(salt)}$${toBase64Url(hash)}`;
}

export async function verifyPassword(
  password: string,
  stored: string,
  pepper?: string
): Promise<boolean> {
  const iterations = parseIterations(stored);
  if (iterations === null) return false;

  const parts = stored.split("$");
  const salt = fromBase64Url(parts[2]);
  const expected = fromBase64Url(parts[3]);
  const actual = await derive(password, salt, iterations, pepper);

  // 长度不等时 timingSafeEqual 也无法比较，直接判否
  if (actual.length !== expected.length) return false;
  return timingSafeEqual(actual, expected);
}

/** 读出哈希里记录的迭代次数；格式不合法返回 null */
export function parseIterations(stored: string): number | null {
  const parts = stored.split("$");
  if (parts.length !== 4 || parts[0] !== ALGORITHM) return null;
  const iterations = Number(parts[1]);
  return Number.isInteger(iterations) && iterations > 0 ? iterations : null;
}

/**
 * 邮箱不存在时也要跑一次等价开销的哈希。
 * 否则「立即返回失败」与「算完再失败」的响应时间差会暴露该邮箱是否注册过。
 */
export async function fakeVerifyPassword(
  iterations: number,
  pepper?: string
): Promise<void> {
  const fake = `${ALGORITHM}$${iterations}$${toBase64Url(randomBytes(SALT_BYTES))}$${toBase64Url(randomBytes(KEY_BITS / 8))}`;
  await verifyPassword("fake-password-for-timing", fake, pepper);
}
