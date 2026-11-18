-- A mailbox can let other mailboxes of the SAME customer into one of its
-- folders: the shared info@ that three people answer, without a password
-- that three people know and without a mail program copying everything to
-- a fourth place.
--
-- Only inside one customer, and that is not a rule of the panel alone:
-- every customer has its own system user (mda_users: uid = 2000000 +
-- customer number) and its mail directory is 0700, so one customer's
-- Dovecot process cannot read another's files even if an ACL said so.
--
-- The rights themselves live where Dovecot keeps them (the dovecot-acl
-- file of the folder, written with doveadm by the root helper). This
-- table is what the panel shows and what it writes again after a restore,
-- the same way the spam scripts and the DKIM keys are written again.

CREATE TABLE mailbox_shares (
    owner_id   uuid NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    with_id    uuid NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    folder     text NOT NULL,              -- INBOX or a folder of the owner
    rights     text NOT NULL,              -- 'read' or 'write'
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (owner_id, with_id, folder),
    CHECK (owner_id <> with_id),
    CHECK (rights IN ('read', 'write'))
);
CREATE INDEX mailbox_shares_with ON mailbox_shares (with_id);
