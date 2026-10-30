-- Spam settings (0.7): how much spam goes to Junk, for the customer and,
-- if set, for one mailbox; allowed and blocked senders of a mailbox. The
-- mail helper turns them into each mailbox's Sieve spam script.
ALTER TABLE customers
    ADD COLUMN spam_level text NOT NULL DEFAULT 'normal' CHECK (spam_level IN ('off', 'relaxed', 'normal', 'strict'));
ALTER TABLE mailboxes
    ADD COLUMN spam_level text NOT NULL DEFAULT '' CHECK (spam_level IN ('', 'off', 'relaxed', 'normal', 'strict')),
    ADD COLUMN spam_allow text[] NOT NULL DEFAULT '{}' CHECK (cardinality(spam_allow) <= 200),
    ADD COLUMN spam_block text[] NOT NULL DEFAULT '{}' CHECK (cardinality(spam_block) <= 200);

-- What the mail helper reads to write the scripts.
CREATE VIEW mda_spam AS
    SELECT m.address, m.customer_id,
           2000000 + c.number AS uid,
           '/var/vmail/' || c.id || '/' || d.name || '/' || m.local_part AS home,
           COALESCE(NULLIF(m.spam_level, ''), c.spam_level) AS level,
           m.spam_allow AS allow, m.spam_block AS block
    FROM mailboxes m JOIN domains d ON d.id = m.domain_id JOIN customers c ON c.id = m.customer_id
    WHERE c.status <> 'terminated';
