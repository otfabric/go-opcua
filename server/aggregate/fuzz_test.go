// SPDX-License-Identifier: MIT

package aggregate

import (
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
)

// FuzzCalculate calculates every Aggregate for requests and raw values a
// client and a history provider control: the time domain, the
// ProcessingInterval, the configuration and the raw values with their
// times, values and statuses. It holds when nothing panics, every interval
// has a value with the request's timestamp rules, and a Bad value carries no
// value.
func FuzzCalculate(f *testing.F) {
	f.Add(int64(0), int64(100), int64(10), uint8(0), uint8(100), uint8(100), uint8(0), []byte{0, 1, 2, 10, 3, 4, 20, 5, 6})
	f.Add(int64(100), int64(0), int64(7), uint8(3), uint8(50), uint8(50), uint8(7), []byte{5, 0x80, 9, 6, 0x40, 1})
	f.Add(int64(0), int64(50), int64(0), uint8(255), uint8(0), uint8(100), uint8(1), []byte{})
	f.Fuzz(func(t *testing.T, start, end, pi int64, flags, bad, goodPct, which uint8, raw []byte) {
		fs := Functions()
		cfg := Config{
			TreatUncertainAsBad:    flags&1 != 0,
			UseSlopedExtrapolation: flags&2 != 0,
			Stepped:                flags&4 != 0,
			PercentDataBad:         bad,
			PercentDataGood:        goodPct,
		}
		// Times in seconds of a small range, so that the intervals stay few.
		r := Request{
			Aggregate:          fs[int(which)%len(fs)],
			Start:              t0.Add(time.Duration(start%1000) * time.Second),
			End:                t0.Add(time.Duration(end%1000) * time.Second),
			ProcessingInterval: time.Duration(pi%200) * time.Second,
			Config:             cfg,
		}
		// Each raw value is three bytes: time, value, status.
		var dvs []*ua.DataValue
		for i := 0; i+2 < len(raw); i += 3 {
			dv := &ua.DataValue{
				EncodingMask:    ua.DataValueSourceTimestamp | ua.DataValueStatusCode | ua.DataValueValue,
				SourceTimestamp: t0.Add(time.Duration(raw[i]) * time.Second),
				Value:           ua.MustVariant(float64(int8(raw[i+1]))),
			}
			switch raw[i+2] % 5 {
			case 1:
				dv.Status = ua.StatusUncertain
			case 2:
				dv.Status = ua.StatusBad
			case 3:
				dv.Status = ua.StatusBadNoData
			case 4:
				dv.Value = ua.MustVariant(raw[i+1]&1 == 0)
			}
			dvs = append(dvs, dv)
		}
		got, st := r.Calculate(dvs)
		if st != r.Check() {
			t.Fatalf("status %v, Check %v", st, r.Check())
		}
		if st != ua.StatusOK {
			return
		}
		if len(got) != r.Intervals() {
			t.Fatalf("%d values for %d intervals", len(got), r.Intervals())
		}
		for _, dv := range got {
			if isBad(dv.Status) && dv.Value != nil {
				t.Fatalf("Bad value %v with a value", dv.Status)
			}
		}
	})
}
