-- Mail from websites (emailzit-sendmail, INTEGRATION P7): counted per
-- hosting account (web_uid) instead of per mailbox, under the same customer
-- limits; a hosting account that keeps trying far beyond its limit is
-- blocked like a mailbox.
ALTER TABLE send_log
    ALTER COLUMN mailbox_id DROP NOT NULL,
    ADD COLUMN web_uid int,
    ADD CONSTRAINT send_log_who CHECK ((mailbox_id IS NULL) <> (web_uid IS NULL));
CREATE INDEX send_log_web ON send_log (web_uid, at) WHERE web_uid IS NOT NULL;

ALTER TABLE send_refused
    ALTER COLUMN mailbox_id DROP NOT NULL,
    ADD COLUMN web_uid int,
    ADD CONSTRAINT send_refused_who CHECK ((mailbox_id IS NULL) <> (web_uid IS NULL));
CREATE INDEX send_refused_web ON send_refused (web_uid, at) WHERE web_uid IS NOT NULL;

ALTER TABLE customer_web_uids
    ADD COLUMN send_blocked boolean NOT NULL DEFAULT false;
