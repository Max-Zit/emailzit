-- Four-eyes approval (0.7): a risky change by staff waits until another
-- administrator approves it. The form values are sealed with the server key
-- (they may hold a password).
CREATE TABLE approvals (
    id           bigserial PRIMARY KEY,
    action       text NOT NULL,
    path         text NOT NULL,
    path_values  jsonb NOT NULL DEFAULT '{}',
    form         text NOT NULL,
    summary      text NOT NULL DEFAULT '',
    requested_by bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    requested_at timestamptz NOT NULL DEFAULT now(),
    status       text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
    decided_by   bigint REFERENCES users(id) ON DELETE SET NULL,
    decided_at   timestamptz
);
CREATE INDEX approvals_pending ON approvals (requested_at) WHERE status = 'pending';
