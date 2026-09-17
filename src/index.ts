import { Hono } from "hono";
import type { AppEnv } from "./env";
import { fail } from "./lib/http";
import { publicJwks } from "./lib/jwt";
import { adminRoute } from "./routes/admin";
import { authRoute } from "./routes/auth";
import { meRoute } from "./routes/me";

const app = new Hono<AppEnv>();

// CORS：本服务只认 Authorization 头里的 Bearer 令牌、不依赖 Cookie，
// 浏览器不会自动携带凭证，因此跨域放行的风险可控。
// ALLOWED_ORIGINS 留空表示允许所有来源，生产环境建议收敛到具体域名。
app.use("*", async (c, next) => {
  const origin = c.req.header("Origin");
  const allowed = (c.env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  const originAllowed = Boolean(origin) && (allowed.length === 0 || allowed.includes(origin!));

  if (c.req.method === "OPTIONS") {
    const headers = new Headers({
      "Access-Control-Allow-Methods": "GET,POST,PATCH,DELETE,OPTIONS",
      "Access-Control-Allow-Headers": "Authorization,Content-Type",
      "Access-Control-Max-Age": "86400",
      Vary: "Origin",
    });
    if (originAllowed) headers.set("Access-Control-Allow-Origin", origin!);
    return new Response(null, { status: 204, headers });
  }

  await next();
  if (originAllowed) {
    c.res.headers.set("Access-Control-Allow-Origin", origin!);
    c.res.headers.set("Vary", "Origin");
  }
});

app.get("/", (c) => c.text("User Center is running!"));

// 各业务服务拉取一次即可本地验签，无需回源
app.get("/.well-known/jwks.json", async (c) =>
  c.json(await publicJwks(c.env), 200, { "Cache-Control": "public, max-age=3600" })
);

app.route("/v1/auth", authRoute);
app.route("/v1/me", meRoute);
app.route("/v1/admin", adminRoute);

app.notFound((c) => fail(c, 404, "not_found", "接口不存在"));
app.onError((error, c) => {
  console.error("[user-center]", error);
  return fail(c, 500, "internal_error", "服务器内部错误");
});

export default app;
