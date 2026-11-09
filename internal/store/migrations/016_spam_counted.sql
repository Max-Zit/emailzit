-- Refused outgoing spam counts towards the automatic block only after this
-- time (set when sending is blocked, so lifting the block starts afresh).
ALTER TABLE mailboxes ADD COLUMN spam_counted_from timestamptz NOT NULL DEFAULT '-infinity';
