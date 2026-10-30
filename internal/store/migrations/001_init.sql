CREATE TABLE settings (
    key   text PRIMARY KEY,
    value jsonb NOT NULL
);

-- Mail packages: the limits a customer gets.
CREATE TABLE packages (
    id               bigserial PRIMARY KEY,
    slug             text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    name             text NOT NULL,
    max_domains      int NOT NULL DEFAULT 1 CHECK (max_domains >= 0),
    max_mailboxes    int NOT NULL DEFAULT 5 CHECK (max_mailboxes >= 0),
    max_aliases      int NOT NULL DEFAULT 20 CHECK (max_aliases >= 0),
    storage_mb       int NOT NULL DEFAULT 5120 CHECK (storage_mb >= 0),  -- all mailboxes together; 0 = no limit
    mailbox_mb       int NOT NULL DEFAULT 1024 CHECK (mailbox_mb > 0),   -- default size of a new mailbox
    max_mailbox_mb   int NOT NULL DEFAULT 10240 CHECK (max_mailbox_mb > 0),
    send_per_hour    int NOT NULL DEFAULT 100 CHECK (send_per_hour >= 0), -- per mailbox; 0 = no sending
    send_per_day     int NOT NULL DEFAULT 500 CHECK (send_per_day >= 0),
    customer_per_hour int NOT NULL DEFAULT 300 CHECK (customer_per_hour >= 0),
    rcpt_per_msg     int NOT NULL DEFAULT 50 CHECK (rcpt_per_msg > 0),
    created_at       timestamptz NOT NULL DEFAULT now()
);

-- Customers (the cPanel accounts). number gives the system UID of the
-- customer's mail (2000000 + number), so every customer's mail files belong
-- to a different user.
CREATE TABLE customers (
    id            uuid PRIMARY KEY,
    number        serial UNIQUE,
    external_id   text UNIQUE,
    name          text NOT NULL,
    email         text NOT NULL DEFAULT '',
    package_id    bigint NOT NULL REFERENCES packages(id),
    status        text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'terminated')),
    status_reason text NOT NULL DEFAULT '',
    lang          text NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL DEFAULT now(),
    status_at     timestamptz NOT NULL DEFAULT now()
);

-- Panel accounts: server admins (admin, operator, viewer) and customer
-- logins (role customer, always with customer_id).
CREATE TABLE users (
    id                   bigserial PRIMARY KEY,
    username             text NOT NULL,
    display_name         text NOT NULL DEFAULT '',
    password_hash        text NOT NULL,
    role                 text NOT NULL CHECK (role IN ('admin', 'operator', 'viewer', 'customer')),
    customer_id          uuid REFERENCES customers(id) ON DELETE CASCADE,
    totp_secret          text NOT NULL DEFAULT '',
    totp_enabled         boolean NOT NULL DEFAULT false,
    totp_last_step       bigint NOT NULL DEFAULT 0,
    recovery_codes       text[] NOT NULL DEFAULT '{}',
    must_change_password boolean NOT NULL DEFAULT false,
    disabled             boolean NOT NULL DEFAULT false,
    lang                 text NOT NULL DEFAULT '',
    created_at           timestamptz NOT NULL DEFAULT now(),
    last_login_at        timestamptz,
    CHECK ((role = 'customer') = (customer_id IS NOT NULL))
);
CREATE UNIQUE INDEX users_username ON users (lower(username));

-- Sign-in sessions; only the SHA-256 of the cookie value is stored.
-- stage 'mfa' is a password-verified sign-in waiting for the second factor.
CREATE TABLE sessions (
    token_hash text PRIMARY KEY,
    user_id    bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    stage      text NOT NULL CHECK (stage IN ('mfa', 'full')),
    created_at timestamptz NOT NULL,
    last_seen  timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    ip         text NOT NULL DEFAULT '',
    user_agent text NOT NULL DEFAULT ''
);
CREATE INDEX sessions_user ON sessions (user_id);

-- Addresses blocked after failed sign-ins.
CREATE TABLE login_blocks (
    ip         text PRIMARY KEY,
    until      timestamptz NOT NULL,
    strikes    int NOT NULL,
    reason     text NOT NULL,
    updated_at timestamptz NOT NULL
);

-- Append-only, hash-chained audit log: hash = SHA-256(prev_hash, fields).
CREATE TABLE audit_log (
    id          bigserial PRIMARY KEY,
    at          timestamptz NOT NULL,
    username    text NOT NULL,
    ip          text NOT NULL,
    action      text NOT NULL,
    target      text NOT NULL,
    detail      text NOT NULL,
    prev_hash   text NOT NULL,
    hash        text NOT NULL
);

-- Mail domains. A domain belongs to exactly one customer; on a shared
-- server it must be verified (TXT record) before mail for it is accepted.
CREATE TABLE domains (
    id           uuid PRIMARY KEY,
    customer_id  uuid NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    name         text NOT NULL CHECK (name = lower(name)),
    verified     boolean NOT NULL DEFAULT false,
    verify_token text NOT NULL,
    catch_all    text NOT NULL DEFAULT '',  -- '' = unknown addresses are rejected
    disabled     boolean NOT NULL DEFAULT false,
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX domains_name ON domains (name);
CREATE INDEX domains_customer ON domains (customer_id);

-- Mailboxes. web_password_hash is for webmail and self-service (always
-- with two-factor sign-in); mail programs use app passwords only.
CREATE TABLE mailboxes (
    id                uuid PRIMARY KEY,
    domain_id         uuid NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    customer_id       uuid NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    local_part        text NOT NULL CHECK (local_part = lower(local_part)),
    address           text NOT NULL CHECK (address = lower(address)),
    display_name      text NOT NULL DEFAULT '',
    web_password_hash text NOT NULL DEFAULT '',
    totp_secret       text NOT NULL DEFAULT '',
    totp_enabled      boolean NOT NULL DEFAULT false,
    totp_last_step    bigint NOT NULL DEFAULT 0,
    recovery_codes    text[] NOT NULL DEFAULT '{}',
    quota_mb          int NOT NULL CHECK (quota_mb > 0),
    disabled          boolean NOT NULL DEFAULT false,
    send_blocked      boolean NOT NULL DEFAULT false,
    send_per_hour     int CHECK (send_per_hour >= 0),  -- NULL = from the package
    send_per_day      int CHECK (send_per_day >= 0),
    lang              text NOT NULL DEFAULT '',
    used_bytes        bigint NOT NULL DEFAULT 0,
    used_at           timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    last_login_at     timestamptz
);
CREATE UNIQUE INDEX mailboxes_address ON mailboxes (address);
CREATE INDEX mailboxes_customer ON mailboxes (customer_id);
CREATE INDEX mailboxes_domain ON mailboxes (domain_id);

-- App passwords: the only way for mail programs (IMAP, POP3, SMTP) to sign
-- in. They are random, so a SHA-256 is enough (and fast for IMAP clients
-- that connect often). kind 'webmail' are short-lived tokens of a webmail
-- session, accepted only from the server itself.
CREATE TABLE app_passwords (
    id           uuid PRIMARY KEY,
    mailbox_id   uuid NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    kind         text NOT NULL DEFAULT 'app' CHECK (kind IN ('app', 'webmail')),
    name         text NOT NULL,
    hash         text NOT NULL,  -- hex SHA-256 of the password
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz,
    last_used_at timestamptz,
    last_ip      text NOT NULL DEFAULT ''
);
CREATE INDEX app_passwords_mailbox ON app_passwords (mailbox_id);
CREATE UNIQUE INDEX app_passwords_hash ON app_passwords (hash);

-- Aliases and forwarders: mail for address goes to destinations (local
-- mailboxes or outside addresses). A forwarder of a mailbox that keeps a
-- copy lists the mailbox itself among the destinations.
CREATE TABLE aliases (
    id           uuid PRIMARY KEY,
    domain_id    uuid NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    customer_id  uuid NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    address      text NOT NULL CHECK (address = lower(address)),
    destinations text[] NOT NULL CHECK (cardinality(destinations) BETWEEN 1 AND 50),
    send_as      boolean NOT NULL DEFAULT false,  -- local destination mailboxes may send as this address
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX aliases_address ON aliases (address);
CREATE INDEX aliases_customer ON aliases (customer_id);

-- ---- What Postfix and Dovecot read (roles postfix and dovecot, peer
-- authentication on the local socket, SELECT on these views only).
-- Suspended customers keep receiving mail but cannot sign in or send;
-- terminated customers' mail is rejected.

CREATE VIEW mta_domains AS
    SELECT d.name FROM domains d JOIN customers c ON c.id = d.customer_id
    WHERE d.verified AND NOT d.disabled AND c.status <> 'terminated';

CREATE VIEW mta_mailboxes AS
    SELECT m.address FROM mailboxes m JOIN domains d ON d.id = m.domain_id JOIN customers c ON c.id = m.customer_id
    WHERE d.verified AND NOT d.disabled AND c.status <> 'terminated';

CREATE VIEW mta_aliases AS
    SELECT a.address, array_to_string(a.destinations, ',') AS destinations
    FROM aliases a JOIN domains d ON d.id = a.domain_id JOIN customers c ON c.id = a.customer_id
    WHERE d.verified AND NOT d.disabled AND c.status <> 'terminated'
    UNION ALL
    -- every mailbox maps to itself, so a catch-all never swallows it
    SELECT m.address, m.address
    FROM mailboxes m JOIN domains d ON d.id = m.domain_id JOIN customers c ON c.id = m.customer_id
    WHERE d.verified AND NOT d.disabled AND c.status <> 'terminated'
      AND NOT EXISTS (SELECT 1 FROM aliases a WHERE a.address = m.address)
    UNION ALL
    SELECT '@' || d.name, d.catch_all
    FROM domains d JOIN customers c ON c.id = d.customer_id
    WHERE d.catch_all <> '' AND d.verified AND NOT d.disabled AND c.status <> 'terminated';

-- Who may use a sender address: the mailbox itself, and the local
-- mailboxes of an alias marked send_as (same customer only).
CREATE VIEW mta_sender_logins AS
    SELECT m.address AS sender, m.address AS login
    FROM mailboxes m JOIN customers c ON c.id = m.customer_id
    WHERE c.status = 'active' AND NOT m.disabled AND NOT m.send_blocked
    UNION ALL
    SELECT a.address, m.address
    FROM aliases a JOIN mailboxes m ON m.address = ANY (a.destinations) AND m.customer_id = a.customer_id
    JOIN customers c ON c.id = a.customer_id
    WHERE a.send_as AND c.status = 'active' AND NOT m.disabled AND NOT m.send_blocked;

-- Dovecot users: every customer has its own system user; mail lives in
-- /var/vmail/<customer>/<domain>/<local part>.
CREATE VIEW mda_users AS
    SELECT m.address AS username,
           2000000 + c.number AS uid,
           2000000 + c.number AS gid,
           '/var/vmail/' || c.id || '/' || d.name || '/' || m.local_part AS home,
           m.quota_mb AS quota_mb
    FROM mailboxes m JOIN domains d ON d.id = m.domain_id JOIN customers c ON c.id = m.customer_id
    WHERE c.status <> 'terminated';

-- Sign-in of mail programs: an app password (or a webmail token) of an
-- active mailbox of an active customer.
CREATE VIEW mda_logins AS
    SELECT m.address AS username, p.hash, p.kind,
           2000000 + c.number AS uid,
           '/var/vmail/' || c.id || '/' || d.name || '/' || m.local_part AS home
    FROM app_passwords p JOIN mailboxes m ON m.id = p.mailbox_id
    JOIN domains d ON d.id = m.domain_id JOIN customers c ON c.id = m.customer_id
    WHERE c.status = 'active' AND NOT m.disabled AND NOT d.disabled AND d.verified
      AND (p.expires_at IS NULL OR p.expires_at > now());

-- Sign-in sessions of mail users (webmail and their own settings).
CREATE TABLE mail_sessions (
    token_hash text PRIMARY KEY,
    mailbox_id uuid NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    stage      text NOT NULL CHECK (stage IN ('mfa', 'enroll', 'full')),
    created_at timestamptz NOT NULL,
    last_seen  timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    ip         text NOT NULL DEFAULT '',
    user_agent text NOT NULL DEFAULT ''
);
CREATE INDEX mail_sessions_mailbox ON mail_sessions (mailbox_id);
