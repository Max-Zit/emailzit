# EmailZit: written by the root helper. Postfix talks to Rspamd as a milter.
milter = yes;
timeout = 120s;
bind_socket = "127.0.0.1:11332";
upstream "local" {
  default = yes;
  self_scan = yes;
}
