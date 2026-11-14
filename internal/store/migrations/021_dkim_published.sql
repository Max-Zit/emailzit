-- EmailZit signs a domain only while its DKIM record really is in the DNS.
-- A key that was never published makes every signature fail at the
-- receiver (HostZit found this on dnstest.maxzit.com, where P6 refused to
-- publish the key). The hourly check in the panel sets this column.

ALTER TABLE domains ADD COLUMN dkim_published boolean NOT NULL DEFAULT false;

-- Keep signing what is signed today; the check only switches a domain off
-- when the DNS clearly says the record is missing.
UPDATE domains SET dkim_published = true WHERE dkim_selector <> '';
