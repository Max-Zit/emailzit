-- Outgoing mail of signed-in mailboxes, one row per accepted message
-- (rcpts = number of recipients): the sending limits count recipients.
CREATE TABLE send_log (
    id          bigserial PRIMARY KEY,
    at          timestamptz NOT NULL DEFAULT now(),
    mailbox_id  uuid NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    customer_id uuid NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    rcpts       int NOT NULL CHECK (rcpts > 0),
    client_ip   text NOT NULL DEFAULT ''
);
CREATE INDEX send_log_mailbox ON send_log (mailbox_id, at);
CREATE INDEX send_log_customer ON send_log (customer_id, at);

-- Attempts refused by a limit (abuse detection: a mailbox that keeps trying
-- far beyond its limit is blocked).
CREATE TABLE send_refused (
    id         bigserial PRIMARY KEY,
    at         timestamptz NOT NULL DEFAULT now(),
    mailbox_id uuid NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    reason     text NOT NULL
);
CREATE INDEX send_refused_mailbox ON send_refused (mailbox_id, at);

-- DKIM: the active key of a domain (private key sealed with the server key)
-- and, during a rotation, the next one.
ALTER TABLE domains
    ADD COLUMN dkim_selector  text NOT NULL DEFAULT '',
    ADD COLUMN dkim_private   text NOT NULL DEFAULT '',
    ADD COLUMN dkim_public    text NOT NULL DEFAULT '',
    ADD COLUMN dkim_created   timestamptz;
