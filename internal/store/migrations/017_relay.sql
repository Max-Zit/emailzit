-- The relay login of the HostZit link (INTEGRATION.md E3): when HostZit
-- runs on another server, the websites there send their mail through
-- EmailZit's own submission server with this login. It is not a mailbox:
-- it cannot sign in to IMAP or the webmail, it lives only here, and the
-- pairing hands it to HostZit, so nobody types it anywhere.
CREATE TABLE relay_logins (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username   text NOT NULL UNIQUE,
    hash       text NOT NULL,            -- sha256 (hex) of the password
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used  timestamptz,
    disabled   boolean NOT NULL DEFAULT false
);

-- What the relay sent or refused, so the customer sees the mail of their
-- websites and the weekly report counts it. The queue ID ties a message to
-- the delivery log (mail_log), which then shows whether it arrived or
-- bounced.
CREATE TABLE relay_log (
    id          bigserial PRIMARY KEY,
    at          timestamptz NOT NULL DEFAULT now(),
    customer_id uuid REFERENCES customers(id) ON DELETE CASCADE,
    sender      text NOT NULL,
    rcpts       int NOT NULL DEFAULT 0,
    queue_id    text NOT NULL DEFAULT '',
    status      text NOT NULL CHECK (status IN ('sent', 'refused')),
    reason      text NOT NULL DEFAULT '',
    client_ip   text NOT NULL DEFAULT ''
);
CREATE INDEX relay_log_at ON relay_log (at);
CREATE INDEX relay_log_customer ON relay_log (customer_id, at);
CREATE INDEX relay_log_sdom ON relay_log ((split_part(sender, '@', 2)), at);

-- Relayed mail counts towards the customer's limit like mail of a mailbox
-- or of a hosting account on this server.
ALTER TABLE send_log
    DROP CONSTRAINT send_log_who,
    ADD COLUMN relay boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT send_log_who
        CHECK ((mailbox_id IS NOT NULL)::int + (web_uid IS NOT NULL)::int + relay::int = 1);
