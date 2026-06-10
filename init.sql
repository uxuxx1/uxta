CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  login VARCHAR(50) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  display_name VARCHAR(100) NOT NULL DEFAULT '',
  bio TEXT DEFAULT '',
  avatar TEXT DEFAULT '',
  twofa_secret TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE messages (
  id SERIAL PRIMARY KEY,
  from_id INT REFERENCES users(id) ON DELETE CASCADE,
  to_id INT REFERENCES users(id) ON DELETE CASCADE,
  text TEXT NOT NULL,
  file_uuid UUID,
  file_name TEXT,
  file_size INT,
  file_deleted BOOLEAN DEFAULT FALSE,
  sent_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE blocks (
  blocker_id INT REFERENCES users(id) ON DELETE CASCADE,
  blocked_id INT REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (blocker_id, blocked_id)
);

CREATE INDEX idx_messages_pair ON messages(from_id, to_id);
CREATE INDEX idx_messages_time ON messages(sent_at);
