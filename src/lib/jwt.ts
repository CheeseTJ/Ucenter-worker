// 访问令牌：Ed25519(EdDSA) 签名的 JWT
//
// 用非对称签名的意义：业务服务只需要公钥就能本地验签，
// 私钥始终留在 Worker 的 secret 里，泄露公钥不构成风险。
import type { Env } from "../env";
import { fromBase64Url, toBase64Url, utf8 } from "./bytes";

export interface AccessTokenInput {
  userId: string;
  /** 放进声明里，业务服务据此做白名单/展示，免去回源查 /v1/me */
  email: string;
  /** user | admin，用户中心自己的管理接口据此放行 */
  role: string;
  /** 目标应用（JWT 的 aud），业务服务据此判断该令牌是否有权访问自己 */
  app: string;
  deviceId: string;
  jti: string;
}

export interface AccessClaims {
  iss: string;
  sub: string;
  aud: string;
  iat: number;
  exp: number;
  jti: string;
  device_id: string;
  scope: string;
  email: string;
  role: string;
}

interface SigningKey {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  publicJwk: JsonWebKey;
  kid: string;
}

// 模块级缓存：isolate 存活期间复用，避免每个请求都重新 importKey
let cache: { source: string; key: SigningKey } | null = null;

async function getSigningKey(env: Env): Promise<SigningKey> {
  if (cache && cache.source === env.JWT_PRIVATE_JWK) return cache.key;

  const jwk = JSON.parse(env.JWT_PRIVATE_JWK) as JsonWebKey;
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || !jwk.x || !jwk.d) {
    throw new Error("JWT_PRIVATE_JWK 必须是含 x 与 d 的 Ed25519 私钥 JWK");
  }

  // 只挑必要字段重建 JWK：各家导出的 alg 取值不统一（Node 写 "Ed25519"，
  // 而 RFC 8037 规定为 "EdDSA"），workerd 会因 alg 与曲线不匹配而直接拒绝导入。
  // 不透传 ext / key_ops / alg，避免被外部工具的导出格式绑架。
  const importJwk: JsonWebKey = {
    kty: "OKP",
    crv: "Ed25519",
    x: jwk.x,
    d: jwk.d,
  };
  const privateKey = await crypto.subtle.importKey(
    "jwk",
    importJwk,
    { name: "Ed25519" },
    false,
    ["sign"]
  );
  // 公钥可以直接从私钥 JWK 的 x 推导，因此只需要托管一个 secret
  const publicJwk: JsonWebKey = { kty: "OKP", crv: "Ed25519", x: jwk.x };
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    publicJwk,
    { name: "Ed25519" },
    false,
    ["verify"]
  );

  // kid 由公钥指纹生成，轮换密钥时各业务服务能自动区分新旧公钥
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", fromBase64Url(jwk.x))
  );
  const kid = toBase64Url(digest).slice(0, 16);

  const key: SigningKey = { privateKey, publicKey, publicJwk, kid };
  cache = { source: env.JWT_PRIVATE_JWK, key };
  return key;
}

export async function signAccessToken(
  env: Env,
  issuer: string,
  input: AccessTokenInput,
  ttlSeconds: number,
  nowSeconds: number
): Promise<string> {
  const { privateKey, kid } = await getSigningKey(env);

  const header = { alg: "EdDSA", typ: "JWT", kid };
  const claims: AccessClaims = {
    iss: issuer,
    sub: input.userId,
    aud: input.app,
    iat: nowSeconds,
    exp: nowSeconds + ttlSeconds,
    jti: input.jti,
    device_id: input.deviceId,
    scope: "user",
    email: input.email,
    role: input.role,
  };

  const signingInput = `${toBase64Url(utf8(JSON.stringify(header)))}.${toBase64Url(
    utf8(JSON.stringify(claims))
  )}`;
  const signature = new Uint8Array(
    await crypto.subtle.sign({ name: "Ed25519" }, privateKey, utf8(signingInput))
  );
  return `${signingInput}.${toBase64Url(signature)}`;
}

/** 验签并校验过期时间；失败一律返回 null，由调用方决定响应 */
export async function verifyAccessToken(
  env: Env,
  token: string,
  nowSeconds: number
): Promise<AccessClaims | null> {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [encodedHeader, encodedClaims, encodedSignature] = parts;

  const { publicKey } = await getSigningKey(env);

  let header: { alg?: string };
  try {
    header = JSON.parse(new TextDecoder().decode(fromBase64Url(encodedHeader)));
  } catch {
    return null;
  }
  if (header.alg !== "EdDSA") return null;

  const signatureOk = await crypto.subtle.verify(
    { name: "Ed25519" },
    publicKey,
    fromBase64Url(encodedSignature),
    utf8(`${encodedHeader}.${encodedClaims}`)
  );
  if (!signatureOk) return null;

  let claims: AccessClaims;
  try {
    claims = JSON.parse(new TextDecoder().decode(fromBase64Url(encodedClaims)));
  } catch {
    return null;
  }
  if (typeof claims.exp !== "number" || claims.exp <= nowSeconds) return null;
  return claims;
}

/** JWKS 公钥集，供各业务服务本地验签 */
export async function publicJwks(
  env: Env
): Promise<{ keys: Record<string, unknown>[] }> {
  const { publicJwk, kid } = await getSigningKey(env);
  return { keys: [{ ...publicJwk, kid, alg: "EdDSA", use: "sig" }] };
}
