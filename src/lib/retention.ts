// 保留策略：定期清理过期的登录审计记录
//
// login_attempts 是只进不出的表，没有清理就会无限增长。D1 免费套餐单库上限 500 MB，
// 正常使用几十年也到不了，但一旦有人拿登录接口撞库，每失败一次就落一行，
// 短时间内就能把库顶满——所以必须给它一个有上界的保留策略。
import type { Env } from "../env";
import { retentionDays } from "./config";

// 单次 DELETE 的行数上限。D1 文档明确：一条语句修改几十万行会超出执行限制，必须分批。
// 每批 2000 行、最多 15 批（3 万行/次）：日常量远小于一批，积压时也能较快收敛。
const BATCH = 2000;
const MAX_BATCHES = 15;

/** 删除 cutoff 之前的审计记录，返回删除行数 */
export async function purgeOldAttempts(env: Env, nowSeconds: number): Promise<number> {
  const cutoff = nowSeconds - retentionDays(env) * 86400;
  let removed = 0;

  for (let i = 0; i < MAX_BATCHES; i++) {
    const result = await env.DB.prepare(
      "DELETE FROM login_attempts WHERE id IN (SELECT id FROM login_attempts WHERE at < ? LIMIT ?)"
    )
      .bind(cutoff, BATCH)
      .run();

    const changes = result.meta.changes ?? 0;
    removed += changes;
    // 不足一批说明已清空，无需继续
    if (changes < BATCH) break;
  }

  if (removed >= BATCH * MAX_BATCHES) {
    console.warn(`[user-center] 审计清理单次已达上限 ${removed} 行，剩余留待下次执行`);
  }
  return removed;
}
