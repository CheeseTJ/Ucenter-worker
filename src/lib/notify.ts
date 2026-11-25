import type { Env } from "../env";

/**
 * 邮件通知：调用内部邮件网关（Mail-api）发信。
 *
 * 为什么走网关而不是 Worker 直连 SMTP：
 * Cloudflare Workers 运行时不支持裸 TCP socket（标准 SMTP 需要），
 * 只有付费版才有 `cloudflare:sockets`。所以 Worker 无法自己连 SMTP 服务器，
 * 必须通过 HTTP 接口转发。
 *
 * 设计原则：**通知失败绝不影响主流程**。
 * 发信只是附带能力，如果因为网关抖动导致登录接口 500，那是本末倒置。
 * 所以 notify() 永远不抛异常，只写日志。
 */

/** 发送一封通知邮件。失败时静默（仅记录），不打断调用方。 */
export async function notify(
  env: Env,
  subject: string,
  html: string,
  fromName = "Ucenter",
): Promise<boolean> {
  const url = env.MAIL_API_URL;
  const to = (env.MAIL_TO || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  // 未配置就跳过 —— 本地开发和不需要通知的部署不该因此报错
  if (!url || to.length === 0) return false;

  try {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (env.MAIL_API_TOKEN) {
      headers["Authorization"] = `Bearer ${env.MAIL_API_TOKEN}`;
    }

    const resp = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify({ from_name: fromName, to, subject, html }),
      // Workers 的 fetch 没有单请求超时参数，用 AbortSignal 兜住
      signal: AbortSignal.timeout(15000),
    });

    if (!resp.ok) {
      const text = await resp.text().catch(() => "");
      console.warn(
        `[notify] 网关返回 ${resp.status}: ${text.slice(0, 200)}`,
      );
      return false;
    }
    return true;
  } catch (err) {
    // 网络错误、超时、网关未启动 —— 都不能影响调用方
    console.warn(`[notify] 发送失败: ${(err as Error).message}`);
    return false;
  }
}

/** HTML 转义，防止用户可控内容（邮箱、IP）破坏邮件结构。 */
export function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/** 行渲染辅助：统一的标签/值排版，避免各处手拼 HTML 风格不一。 */
export function row(label: string, value: string): string {
  return (
    `<tr>` +
    `<td style="padding:6px 12px 6px 0;color:#6b7280;white-space:nowrap">${esc(label)}</td>` +
    `<td style="padding:6px 0;color:#111827">${esc(value)}</td>` +
    `</tr>`
  );
}

/** 把若干行包成一个表格。 */
export function table(rows: string): string {
  return `<table style="border-collapse:collapse;font-size:13px">${rows}</table>`;
}

/** 邮件外壳：统一标题与页脚，所有通知共用。 */
export function wrap(title: string, body: string): string {
  return (
    `<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;` +
    `max-width:560px;margin:0 auto;padding:24px;color:#1f2937">` +
    `<h2 style="margin:0 0 14px;font-size:17px">${esc(title)}</h2>` +
    body +
    `<p style="margin:20px 0 0;font-size:12px;color:#9ca3af">` +
    `Ucenter 自动通知 · ${new Date().toISOString().replace("T", " ").slice(0, 19)} UTC` +
    `</p></div>`
  );
}
