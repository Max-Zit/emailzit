-- Several HostZit servers on one EmailZit and one HostZit on several
-- EmailZit servers (INTEGRATION.md "Many HostZit and many EmailZit
-- servers", E7–E13). A link is a pair of servers: each link keeps its own
-- token, relay login, addresses and scope, and nothing of one link ever
-- touches another. The single link of the setting "hostzit" becomes the
-- first row.

CREATE TABLE hostzit_links (
    id          bigserial PRIMARY KEY,
    url         text NOT NULL UNIQUE,
    server_name text NOT NULL DEFAULT '',
    token       text NOT NULL DEFAULT '',     -- sealed hzt_ token of that HostZit
    insecure    boolean NOT NULL DEFAULT false,
    pin         text NOT NULL DEFAULT '',     -- SHA-256 of its public key
    addresses   text[] NOT NULL DEFAULT '{}', -- where that HostZit calls from
    token_id    text NOT NULL DEFAULT '',     -- the ezt_ token we gave it
    scope_all   boolean NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now(),
    last_call   timestamptz                   -- when we last reached it
);

-- The customers an "assigned" link serves (E13): with scope_all = false
-- its token reads, changes and opens one-time links only for these, its
-- relay login takes only their domains, and DNS is published only for
-- them. Everything else answers as if it did not exist.
CREATE TABLE hostzit_link_customers (
    link_id     bigint NOT NULL REFERENCES hostzit_links(id) ON DELETE CASCADE,
    customer_id uuid   NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    PRIMARY KEY (link_id, customer_id)
);

-- Every link has its own relay login for the websites of its HostZit.
ALTER TABLE relay_logins ADD COLUMN link_id bigint REFERENCES hostzit_links(id) ON DELETE CASCADE;

INSERT INTO hostzit_links(url, server_name, token, insecure, pin, addresses, token_id, created_at)
SELECT s.value->>'url', COALESCE(s.value->>'server_name', ''), COALESCE(s.value->>'token', ''),
       COALESCE((s.value->>'insecure')::boolean, false), COALESCE(s.value->>'pin', ''),
       COALESCE(ARRAY(SELECT jsonb_array_elements_text(s.value->'addresses')), '{}'),
       COALESCE(s.value->>'token_id', ''), now()
FROM settings s WHERE s.key = 'hostzit' AND COALESCE(s.value->>'url', '') <> '';

UPDATE relay_logins SET link_id = (SELECT id FROM hostzit_links ORDER BY id LIMIT 1);
DELETE FROM relay_logins WHERE link_id IS NULL;

DELETE FROM settings WHERE key = 'hostzit';
