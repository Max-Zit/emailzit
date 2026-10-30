-- Delivery log ("Track delivery"), written by the root helper from the
-- Postfix log; kept 30 days.
CREATE TABLE mail_log (
    id        bigserial PRIMARY KEY,
    at        timestamptz NOT NULL,
    queue_id  text NOT NULL DEFAULT '',
    sender    text NOT NULL DEFAULT '',
    recipient text NOT NULL DEFAULT '',
    status    text NOT NULL,
    relay     text NOT NULL DEFAULT '',
    dsn       text NOT NULL DEFAULT '',
    info      text NOT NULL DEFAULT ''
);
CREATE INDEX mail_log_at ON mail_log (at);
CREATE INDEX mail_log_recipient ON mail_log (recipient);
CREATE INDEX mail_log_sender ON mail_log (sender);
-- the domain parts, for the customer's view
CREATE INDEX mail_log_rdom ON mail_log ((split_part(recipient, '@', 2)));
CREATE INDEX mail_log_sdom ON mail_log ((split_part(sender, '@', 2)));
