package mailhelper

import "testing"

// The helper checks every request before it runs as root. A ban needs a real
// address; 0 minutes lifts the block, "all" lifts every block.
func TestValidateBan(t *testing.T) {
	cases := []struct {
		name    string
		r       Request
		wantErr bool
	}{
		{"block an address", Request{Action: ActionBan, IP: "203.0.113.5", Minutes: 60}, false},
		{"block an IPv6 address", Request{Action: ActionBan, IP: "2001:db8::5", Minutes: 60}, false},
		{"lift one address", Request{Action: ActionBan, IP: "203.0.113.5", Minutes: 0}, false},
		{"lift every block", Request{Action: ActionBan, IP: "all", Minutes: 0}, false},
		{"not an address", Request{Action: ActionBan, IP: "example.com", Minutes: 60}, true},
		{"the server itself", Request{Action: ActionBan, IP: "127.0.0.1", Minutes: 60}, true},
		{"longer than a week", Request{Action: ActionBan, IP: "203.0.113.5", Minutes: 10081}, true},
		{"negative time", Request{Action: ActionBan, IP: "203.0.113.5", Minutes: -1}, true},
		{"all with a time", Request{Action: ActionBan, IP: "all", Minutes: 60}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := c.r
			err := r.Validate()
			if (err != nil) != c.wantErr {
				t.Fatalf("Validate() = %v, want error: %v", err, c.wantErr)
			}
		})
	}
}
