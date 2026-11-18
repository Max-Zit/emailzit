-- A session remembers how it was opened. "sso" is a one-time link from a
-- linked HostZit or the billing system: that system already signed the
-- customer in, so, like a cPanel session from WHM or WHMCS, the session is
-- not sent to the first password change, and the customer may choose a
-- password without the current one while they never chose one.
ALTER TABLE sessions ADD COLUMN via text NOT NULL DEFAULT '';
