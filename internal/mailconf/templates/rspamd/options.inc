# EmailZit: written by the root helper.
local_addrs = [127.0.0.0/8, ::1];
dns {
    timeout = 1s;
    sockets = 16;
    retransmits = 5;
{{- if .Unbound}}
    # the local resolver (Unbound): block lists refuse public resolvers
    nameserver = ["127.0.0.1:5335"];
{{- end}}
}
