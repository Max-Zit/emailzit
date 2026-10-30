package web

import (
	"strings"
	"testing"

	"github.com/max-zit/emailzit/internal/store"
)

func TestQuotaLevel(t *testing.T) {
	mb := int64(1 << 20)
	for _, c := range []struct {
		used         int64
		warned, want int
	}{
		{50 * mb, 0, 0}, {81 * mb, 0, 80}, {96 * mb, 80, 95}, {75 * mb, 80, 80}, {75 * mb, 0, 0}, {60 * mb, 95, 0}, {100 * mb, 95, 95},
	} {
		if got := quotaLevel(store.QuotaCheck{UsedBytes: c.used, QuotaMB: 100, Warned: c.warned}); got != c.want {
			t.Errorf("used %d MB, warned %d: level %d, want %d", c.used/mb, c.warned, got, c.want)
		}
	}
	subject, body := quotaNotice(store.QuotaCheck{Address: "ana@example.com", UsedBytes: 85 * mb, QuotaMB: 100})
	if subject != "Your mailbox is 85% full" || !strings.Contains(body, "ana@example.com uses 85.0 MB of its 100 MB") {
		t.Errorf("notice: %q / %q", subject, body)
	}
}
