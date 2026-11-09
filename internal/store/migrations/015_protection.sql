-- 0.8: outgoing mail in the delivery log (spam refused on the submission
-- ports counts towards the automatic block), the reason of a refusal, own
-- outbound addresses per customer, the admin notices that were sent.
ALTER TABLE mail_log ADD COLUMN outbound boolean NOT NULL DEFAULT false;
CREATE INDEX mail_log_outbound ON mail_log (at) WHERE outbound AND status = 'rejected';

-- the extra sending address of the customer (Settings -> Outbound
-- addresses); empty = the server's address
ALTER TABLE customers ADD COLUMN outbound_ip text NOT NULL DEFAULT '';

-- what Postfix reads: sender domain -> transport of the address. The name
-- is computed as in mailconf.TransportName ("ezo" + 10 hex digits of
-- SHA-256 of the address).
CREATE VIEW mta_sender_transport AS
    SELECT d.name AS domain, 'ezo' || substr(encode(sha256(convert_to(c.outbound_ip, 'UTF8')), 'hex'), 1, 10) || ':' AS transport
    FROM domains d JOIN customers c ON c.id = d.customer_id
    WHERE c.outbound_ip <> '' AND d.verified AND NOT d.disabled AND c.status <> 'terminated';

-- notices to the administrators (weekly report, block lists, automatic
-- blocks): when each kind was last sent, so a restart sends nothing twice
CREATE TABLE admin_notices (
    kind    text PRIMARY KEY,
    sent_at timestamptz NOT NULL,
    state   text NOT NULL DEFAULT ''
);
