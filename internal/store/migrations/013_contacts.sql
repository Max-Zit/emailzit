-- Webmail (0.7): a signature per mailbox and an address book. Addresses
-- mail was sent to are added by themselves (auto); the user can add, rename
-- and remove entries.
ALTER TABLE mailboxes ADD COLUMN signature text NOT NULL DEFAULT '';
CREATE TABLE contacts (
    id         bigserial PRIMARY KEY,
    mailbox_id uuid NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    name       text NOT NULL DEFAULT '',
    email      text NOT NULL CHECK (email = lower(email)),
    auto       boolean NOT NULL DEFAULT false,
    used_at    timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX contacts_mailbox_email ON contacts (mailbox_id, email);
