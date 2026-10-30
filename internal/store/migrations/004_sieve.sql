-- Auto-reply and filters of a mailbox (the Sieve script is generated from it).
ALTER TABLE mailboxes ADD COLUMN sieve jsonb NOT NULL DEFAULT '{}';
