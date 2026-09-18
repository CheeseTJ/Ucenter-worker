import { Hono } from "hono";
import type { AppEnv, Env } from "./env";
import { fail } from "./lib/http";
import { publicJwks } from "./lib/jwt";
import { purgeOldAttempts } from "./lib/retention";
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

// Cron Trigger：清理过期的登录审计记录（见 wrangler.jsonc 的 triggers）。
// Hono 没有内置的定时入口，按 Workers 约定的对象形式导出。
export default {
  fetch: app.fetch,

  async scheduled(event: ScheduledController, env: Env, ctx: ExecutionContext) {
    // 用 scheduledTime 而不是 Date.now()，保证同一次触发内的时间基准一致
    const nowSeconds = Math.floor(event.scheduledTime / 1000);
    ctx.waitUntil(
      purgeOldAttempts(env, nowSeconds)
        .then((removed) => {
          if (removed > 0) console.log(`[user-center] 已清理 ${removed} 条过期登录审计`);
        })
        .catch((error) => {
          // 清理失败不影响服务，下次触发会继续
          console.error("[user-center] 登录审计清理失败", error);
        })
    );
  },
};
