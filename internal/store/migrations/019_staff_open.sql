-- Staff may open a mailbox (webmail and the user's own pages) to help the
-- customer, the way a hosting panel does: customers often ask whether a
-- message arrived. Every time is written to the audit log, and the mail
-- user sees on their own page when it last happened.

ALTER TABLE mailboxes ADD COLUMN staff_opened_at timestamptz;
ALTER TABLE mailboxes ADD COLUMN staff_opened_by text NOT NULL DEFAULT '';
