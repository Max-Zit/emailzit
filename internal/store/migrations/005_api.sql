-- REST API tokens (billing systems, HostZit). Only the SHA-256 of the
-- token is stored; scopes limit what a token may do.
CREATE TABLE api_tokens (
    id           uuid PRIMARY KEY,
    name         text NOT NULL,
    hash         text NOT NULL UNIQUE,
    scopes       text[] NOT NULL,
    allowed_ips  text[] NOT NULL DEFAULT '{}',
    created_by   text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz,
    last_used_at timestamptz,
    last_ip      text NOT NULL DEFAULT ''
);

-- Answers of create calls by Idempotency-Key (kept 24 hours).
CREATE TABLE api_idempotency (
    token_id   uuid NOT NULL REFERENCES api_tokens(id) ON DELETE CASCADE,
    key        text NOT NULL,
    status     int NOT NULL,
    body       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (token_id, key)
);

-- One-time sign-in links into the customer panel (60 seconds).
CREATE TABLE sso_tickets (
    hash       text PRIMARY KEY,
    user_id    bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL
);

ALTER TABLE customers ADD COLUMN username text UNIQUE;
