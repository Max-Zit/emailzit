-- DMARC aggregate reports (0.7): every domain receives them at
-- dmarc-reports@<domain> (the rua= address of the suggested DMARC record);
-- Postfix hands that address to "emailzit-server --dmarc-report", which
-- stores the reports here.
CREATE TABLE dmarc_reports (
    id          bigserial PRIMARY KEY,
    domain_id   uuid NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    org         text NOT NULL,
    email       text NOT NULL DEFAULT '',
    report_id   text NOT NULL,
    policy      text NOT NULL DEFAULT '',
    begin_at    timestamptz NOT NULL,
    end_at      timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (domain_id, org, report_id)
);
CREATE INDEX dmarc_reports_domain ON dmarc_reports (domain_id, end_at);
CREATE TABLE dmarc_records (
    report_id   bigint NOT NULL REFERENCES dmarc_reports(id) ON DELETE CASCADE,
    source_ip   inet NOT NULL,
    count       int NOT NULL,
    disposition text NOT NULL DEFAULT '',
    dkim        boolean NOT NULL,
    spf         boolean NOT NULL,
    header_from text NOT NULL DEFAULT ''
);
CREATE INDEX dmarc_records_report ON dmarc_records (report_id);

-- the report address exists for every domain mail is received for
CREATE OR REPLACE VIEW mta_mailboxes AS
    SELECT m.address FROM mailboxes m JOIN domains d ON d.id = m.domain_id JOIN customers c ON c.id = m.customer_id
    WHERE d.verified AND NOT d.disabled AND c.status <> 'terminated'
    UNION ALL
    SELECT 'dmarc-reports@' || name FROM mta_domains;
CREATE VIEW mta_transport AS
    SELECT 'dmarc-reports@' || name AS address, 'emailzit-dmarc:' AS transport FROM mta_domains;
