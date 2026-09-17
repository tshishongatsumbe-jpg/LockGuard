-- LockGuard database schema
-- Run automatically by Database.java on startup

CREATE TABLE IF NOT EXISTS users (
                                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                                     username TEXT UNIQUE NOT NULL,
                                     password_hash TEXT NOT NULL,
                                     failed_attempts INTEGER DEFAULT 0,
                                     locked INTEGER DEFAULT 0,
                                     role TEXT DEFAULT 'USER',
                                     two_factor_secret TEXT,
                                     two_factor_enabled INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS login_attempts (
                                              id INTEGER PRIMARY KEY AUTOINCREMENT,
                                              username TEXT NOT NULL,
                                              timestamp TEXT NOT NULL,
                                              success INTEGER NOT NULL
);