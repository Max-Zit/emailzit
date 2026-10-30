-- Quota warnings (0.7): the highest warning a mailbox got (0, 80, 95 %);
-- back to 0 when it falls below 70 %, so it is warned again later.
ALTER TABLE mailboxes ADD COLUMN quota_warned smallint NOT NULL DEFAULT 0;
