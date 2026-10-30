package web

// pct is part of whole in percent (0 when whole is 0).
func pct(part, whole int) int {
	if whole <= 0 {
		return 0
	}
	return part * 100 / whole
}

func init() {
	funcs["pct"] = pct
}
