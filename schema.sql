-- 用户中心 D1 schema
-- 应用方式：npm run db:local（本地） / npm run db:remote（线上）

-- 账号：只存口令派生结果，绝不存明文
CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  -- active | banned | deleted
  status        TEXT NOT NULL DEFAULT 'active',
  -- admin | user：admin 可访问 /v1/admin/*，user 只能操作自己
  role          TEXT NOT NULL DEFAULT 'user',
  created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  deleted_at    INTEGER
);
-- 注意：CREATE TABLE IF NOT EXISTS 不会给已存在的表补列。
-- 老库升级需手工执行一次（幂等，重复执行会报 duplicate column 可忽略）：
--   ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user';

-- 邀请码：明文不落库，只存哈希
CREATE TABLE IF NOT EXISTS invites (
  code_hash  TEXT PRIMARY KEY,
  note       TEXT NOT NULL DEFAULT '',
  max_uses   INTEGER NOT NULL DEFAULT 1,
  uses       INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- 设备：令牌挂在设备下，支持按设备一键吊销
CREATE TABLE IF NOT EXISTS devices (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL,
  name       TEXT NOT NULL DEFAULT '',
  platform   TEXT NOT NULL DEFAULT '',
  last_seen  INTEGER NOT NULL DEFAULT (unixepoch()),
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);

-- 刷新令牌：只存哈希；family_id 标识同一条旋转链，用于检测令牌被盗后复用
CREATE TABLE IF NOT EXISTS refresh_tokens (
  token_hash  TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL,
  device_id   TEXT NOT NULL,
  family_id   TEXT NOT NULL,
  expires_at  INTEGER NOT NULL,
  created_at  INTEGER NOT NULL DEFAULT (unixepoch()),
  revoked_at  INTEGER,
  replaced_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_refresh_user   ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_family ON refresh_tokens(family_id);

-- 登录审计：既用于排查，也为后续「异地登录提醒」留数据
CREATE TABLE IF NOT EXISTS login_attempts (
  id    INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  ip    TEXT NOT NULL DEFAULT '',
  ok    INTEGER NOT NULL,
  at    INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_attempts_email_at ON login_attempts(email, at);
