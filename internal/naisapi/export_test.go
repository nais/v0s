package naisapi

import "time"

// SetNow replaces the clock used to expire resolved tags.
func (inv *Inventory) SetNow(now func() time.Time) { inv.now = now }
