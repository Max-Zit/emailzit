-- Moving mail from another server into a mailbox (IMAP). The password of
-- the old account is sealed and removed when the import ends.
CREATE TABLE imap_imports (
    id          uuid PRIMARY KEY,
    mailbox_id  uuid NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    customer_id uuid NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    host        text NOT NULL,
    port        int NOT NULL,
    insecure    boolean NOT NULL DEFAULT false,
    username    text NOT NULL,
    password    text NOT NULL DEFAULT '',
    status      text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'done', 'failed')),
    folders     int NOT NULL DEFAULT 0,
    copied      int NOT NULL DEFAULT 0,
    skipped     int NOT NULL DEFAULT 0,
    error       text NOT NULL DEFAULT '',
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz
);
CREATE INDEX imap_imports_mailbox ON imap_imports (mailbox_id, created_at);
