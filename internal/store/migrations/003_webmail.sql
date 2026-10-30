-- The webmail token of a mail user session (sealed with the server key):
-- the webmail signs in to IMAP and SMTP on the server itself with it.
ALTER TABLE mail_sessions ADD COLUMN webmail text NOT NULL DEFAULT '';
