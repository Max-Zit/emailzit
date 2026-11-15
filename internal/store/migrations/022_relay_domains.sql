-- A website on a linked HostZit may send mail for a domain that has no
-- mailbox here only when the PUBLIC DNS of that domain says so: HostZit
-- publishes the record EmailZit chose into the zone and EmailZit reads it
-- back at the domain's own name servers. A zone inside HostZit is no proof
-- on its own, because every hosting account may create a zone for someone
-- else's name; without this a website could send with another customer's
-- domain in From and SPF and DMARC would still pass (HostZit's security
-- review of the relay, 2026-11-14).

CREATE TABLE relay_domains (
    domain      text PRIMARY KEY,
    link_id     bigint NOT NULL REFERENCES hostzit_links(id) ON DELETE CASCADE,
    token       text NOT NULL,                 -- what the record must say
    hz_customer text NOT NULL DEFAULT '',      -- the customer at that HostZit
    proven_at   timestamptz,                   -- when the record was seen
    checked_at  timestamptz NOT NULL DEFAULT now(),
    created_at  timestamptz NOT NULL DEFAULT now()  -- when it was first asked about
);
