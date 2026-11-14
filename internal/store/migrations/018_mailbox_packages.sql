-- A package is the plan of ONE mailbox now (Stefan, 2026-11-14: "da jedan
-- kupac može da ima tri Mail 10, dva Mail 100, jedan Mail 25" — mail is
-- sold per mailbox, so one customer mixes plans). The customer keeps a
-- base package: it holds the limits of the whole customer (domains,
-- aliases, storage, sending of the customer) and is the plan a new
-- mailbox gets when none is chosen.

ALTER TABLE mailboxes ADD COLUMN package_id bigint REFERENCES packages(id);
UPDATE mailboxes m SET package_id = c.package_id FROM customers c WHERE c.id = m.customer_id;
ALTER TABLE mailboxes ALTER COLUMN package_id SET NOT NULL;
CREATE INDEX mailboxes_package ON mailboxes (package_id);

-- How many mailboxes of a plan the customer has (what the customer pays
-- for). A new mailbox of a plan is only made while fewer exist than this.
CREATE TABLE customer_packages (
    customer_id uuid   NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    package_id  bigint NOT NULL REFERENCES packages(id),
    mailboxes   int    NOT NULL CHECK (mailboxes >= 0 AND mailboxes <= 100000),
    PRIMARY KEY (customer_id, package_id)
);

-- What every customer had until now: the mailboxes of the base package.
INSERT INTO customer_packages(customer_id, package_id, mailboxes)
SELECT c.id, c.package_id, p.max_mailboxes FROM customers c JOIN packages p ON p.id = c.package_id;
