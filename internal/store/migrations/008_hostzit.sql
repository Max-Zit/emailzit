-- Linux user IDs of a customer's hosting accounts in HostZit (mail from
-- websites is counted against the customer; INTEGRATION P7).
CREATE TABLE customer_web_uids (
    uid         int PRIMARY KEY CHECK (uid BETWEEN 1000000 AND 1999999),
    customer_id uuid NOT NULL REFERENCES customers(id) ON DELETE CASCADE
);
CREATE INDEX customer_web_uids_customer ON customer_web_uids (customer_id);

-- DNS of a domain kept by HostZit (the records are written there by
-- EmailZit); dns_note tells the last result.
ALTER TABLE domains
    ADD COLUMN dns_managed boolean NOT NULL DEFAULT false,
    ADD COLUMN dns_note    text NOT NULL DEFAULT '',
    ADD COLUMN dns_at      timestamptz;
