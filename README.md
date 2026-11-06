<div align="center">
  <h1>Ucenter · Worker</h1>
  <p>统一身份中心 · Cloudflare Worker + D1，账号 / 设备 / 令牌 / 邀请码</p>
</div>

<div align="center">

![Cloudflare](https://img.shields.io/badge/Cloudflare-Workers-F38020)
![Hono](https://img.shields.io/badge/Hono-4-e36002)
![D1](https://img.shields.io/badge/Storage-D1-003B57)
![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6)
![License](https://img.shields.io/badge/License-MIT-green)

</div>

## 项目定位

一组自托管服务共用的**统一身份中心**：只对外提供 REST API，不管页面。用 Cloudflare
Worker + D1 实现，冷启动免费、全球就近，适合个人/小团队的多应用场景。

下游应用不自己存密码，而是：

1. 把用户送到本中心登录，拿到 JWT
2. 用自己的 `app` 标识校验 JWT 的 `aud`
3. 通过本中心公开的 JWKS 验签，**不需要共享密钥**

```text
Ucenter-web (Vue)  ──登录/注册──>  Ucenter-worker (本仓库)
                                        │
                                        ├──> D1         users / invites /
                                        │               devices / refresh_tokens /
                                        │               login_attempts
                                        └──> JWKS       /.well-known/jwks.json

下游应用 (Imgbed-api / Remind-api / WordRush-api / CICD ...)
        │
        └──拉取 JWKS 验签，按 aud 判断是不是发给自己的
```

## 功能

### 账号
- 注册 / 登录 / 登出，密码哈希存储
- 邀请码准入（非开放注册）
- 角色（admin / user），管理员可查看概览

### 会话与令牌
- Access Token（JWT，短时效）+ Refresh Token（长效、可撤销）
- Refresh Token 落库，登出与撤销即时失效
- JWKS 端点公开，下游自行验签
- 按 `app` 维度签发 `aud`，一个令牌只对目标应用有效

### 设备管理
- 记录登录设备（deviceId），支持单设备与全设备撤销
- 用户可查看自己的活跃设备并踢下线

### 防护
- 撞库限流：基于 Cloudflare Rate Limiting binding，同节点同 key 每分钟限额
- 登录失败计数落库（`login_attempts`）
- 数据保留策略（`lib/retention.ts`）清理过期令牌与日志

## 快速开始

```bash
npm install

# 初始化本地 D1
npm run db:local

# 本地开发
npm run dev
```

部署：

```bash
npm run db:remote     # 首次：建表
npm run deploy        # wrangler deploy
```

### 配置

`wrangler.jsonc` 里的绑定需要改成你自己的：

| 项 | 说明 |
|---|---|
| `account_id` | 你的 Cloudflare 账号 ID |
| `d1_databases[].database_id` | 你新建的 D1 库 ID |
| `ratelimits` | 限流命名空间与阈值 |

> ⚠️ 仓库中的 `account_id` / `database_id` 是原作者的，**请替换为你自己的**。

密钥（JWT 签名私钥等）通过 `wrangler secret put` 配置，不写入仓库。

### 环境变量

```bash
npx wrangler secret put JWT_PRIVATE_KEY
npx wrangler secret put JWT_PUBLIC_KEY
# 以及 APPS（可达的应用标识列表）等，见 src/env.ts
```

## API 一览

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/register` | 注册（需邀请码） |
| POST | `/login` | 登录，返回 access + refresh |
| POST | `/refresh` | 用 refresh token 换新 access token |
| POST | `/logout` | 登出并撤销 refresh token |
| POST | `/password` | 修改密码 |
| GET | `/.well-known/jwks.json` | **公开**，下游验签用 |
| GET | `/me` | 当前用户信息 |
| GET | `/devices` | 我的设备列表 |
| DELETE | `/devices/:id` | 撤销指定设备 |
| GET | `/overview` | 管理概览（admin） |
| GET | `/users` | 用户列表（admin） |
| POST | `/users/:id/revoke` | 强制撤销某用户全部会话（admin） |
| GET/POST | `/invites` | 邀请码管理（admin） |

## 数据表

`users` / `invites` / `devices` / `refresh_tokens` / `login_attempts`，见 `schema.sql`。

> 注意：`CREATE TABLE IF NOT EXISTS` 不会给已存在的表补列，后续加字段需要写迁移。

## 目录结构

```text
src/
  index.ts          Worker 入口与路由挂载
  env.ts            绑定与环境变量类型
  routes/           auth（登录注册）/ me / admin
  middleware/auth.ts  JWT 校验中间件
  lib/
    jwt.ts          签发与验签
    password.ts     密码哈希
    sessions.ts     会话 / refresh token
    token.ts        token 工具
    retention.ts    过期数据清理
    config.ts       配置读取
    http.ts         统一响应
    bytes.ts        编码工具
schema.sql          D1 建表语句
```

## License

[MIT](./LICENSE) © 2026 JuneT
