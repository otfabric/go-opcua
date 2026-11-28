// SPDX-License-Identifier: MIT

package aggregate

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
)

// Annex A of OPC 10000-13 gives the examples of every Aggregate as a CSV
// file, "produced programatically" (§A.1.1). testdata/AggregateExamples.csv
// is Schema/AggregateExamples.csv of the OPC Foundation UA-Nodeset
// repository at the commit of schema/manifest.json (the CSV released with
// 1.05 at http://www.opcfoundation.org/UA/schemas/1.05/AggregateExamples.csv
// has the same content). It holds five raw data sets (Historian1 to
// Historian5, each with its AggregateConfiguration and Stepped Property)
// and the processed values of every standard Aggregate for some of them,
// over 12:00:00 to 12:01:40 in intervals of 5, 16 or 20 seconds.

// annexDay is the day of the examples, which give times only.
var annexDay = time.Date(2012, time.January, 2, 0, 0, 0, 0, time.UTC)

type annexRow struct {
	ts     time.Time
	value  string
	status string
}

type annexTable struct {
	aggregate string
	historian string
	pi        time.Duration
	cfg       Config
	rows      []annexRow
}

type annexFile struct {
	raw    map[string][]*ua.DataValue
	tables []*annexTable
}

func parseAnnexTime(t *testing.T, s string) time.Time {
	t.Helper()
	for _, layout := range []string{"15:04:05.000", "15:04:05"} {
		if v, err := time.Parse(layout, s); err == nil {
			return annexDay.Add(time.Duration(v.Hour())*time.Hour + time.Duration(v.Minute())*time.Minute + time.Duration(v.Second())*time.Second + time.Duration(v.Nanosecond()))
		}
	}
	t.Fatalf("annex: bad time %q", s)
	return time.Time{}
}

// splitCSV splits a line of the file: fields are separated by commas, a
// quoted field may hold commas.
func splitCSV(line string) []string {
	var out []string
	var cur strings.Builder
	quoted := false
	for _, r := range line {
		switch {
		case r == '"':
			quoted = !quoted
		case r == ',' && !quoted:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	return append(out, cur.String())
}

func rawStatus(t *testing.T, s string) ua.StatusCode {
	t.Helper()
	switch s {
	case "Good":
		return ua.StatusOK
	case "Bad":
		return ua.StatusBad
	case "Bad_NoData":
		return ua.StatusBadNoData
	case "Uncertain":
		return ua.StatusUncertain
	}
	t.Fatalf("annex: raw status %q", s)
	return 0
}

func loadAnnex(t *testing.T) *annexFile {
	t.Helper()
	f, err := os.Open("testdata/AggregateExamples.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	af := &annexFile{raw: map[string][]*ua.DataValue{}}
	var (
		processed bool
		aggregate string
		historian string
		table     *annexTable
		cfg       Config
		pi        time.Duration
	)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		fields := splitCSV(line)
		key := strings.TrimSpace(fields[0])
		switch {
		case line == "Start of Processed Data Tables":
			processed = true
		case key == "Aggregate":
			aggregate, table = fields[1], nil
		case strings.HasPrefix(key, "Historian") && len(fields) == 1:
			historian, table, cfg, pi = key, nil, Config{}, 0
		case key == "Processing Interval":
			ms, _ := strconv.Atoi(fields[1])
			pi = time.Duration(ms) * time.Millisecond
		case key == "Stepped":
			cfg.Stepped = fields[1] == "true"
		case key == "Treat Uncertain as Bad":
			cfg.TreatUncertainAsBad = fields[1] == "true"
		case key == "Percent Bad":
			v, _ := strconv.Atoi(fields[1])
			cfg.PercentDataBad = uint8(v)
		case key == "Percent Good":
			v, _ := strconv.Atoi(fields[1])
			cfg.PercentDataGood = uint8(v)
		case key == "Use Sloped Extrapolation":
			cfg.UseSlopedExtrapolation = fields[1] == "true"
		case key == "Timestamp":
			if processed {
				table = &annexTable{aggregate: aggregate, historian: historian, pi: pi, cfg: cfg}
				af.tables = append(af.tables, table)
			}
		case key == "" || len(fields) < 3:
		case !processed:
			// A raw value: Timestamp, Value, StatusCode.
			dv := &ua.DataValue{
				EncodingMask:    ua.DataValueSourceTimestamp | ua.DataValueStatusCode,
				SourceTimestamp: parseAnnexTime(t, key),
				Status:          rawStatus(t, fields[2]),
			}
			switch v := fields[1]; v {
			case "", "undefined":
			case "true", "false":
				dv.Value = ua.MustVariant(v == "true")
			default:
				n, err := strconv.ParseFloat(v, 64)
				if err != nil {
					t.Fatalf("annex: raw value %q", v)
				}
				dv.Value = ua.MustVariant(n)
			}
			if dv.Value != nil {
				dv.EncodingMask |= ua.DataValueValue
			}
			af.raw[historian] = append(af.raw[historian], dv)
		case table != nil:
			table.rows = append(table.rows, annexRow{ts: parseAnnexTime(t, key), value: fields[1], status: fields[2]})
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return af
}

// statusText renders a processed StatusCode as the file does: the code,
// then the data location (Calculated, Interpolated), Partial and
// MultipleValues.
func statusText(st ua.StatusCode) string {
	parts := []string{strings.TrimPrefix(ua.StatusCode(uint32(st)&0xFFFF0000).Symbol(), "Status")}
	if loc := st & ua.StatusCodeHistorianDataLocation; loc == ua.StatusCodeHistorianCalculated {
		parts = append(parts, "Calculated")
	} else if loc == ua.StatusCodeHistorianInterpolated {
		parts = append(parts, "Interpolated")
	}
	if st&ua.StatusCodeHistorianPartial != 0 {
		parts = append(parts, "Partial")
	}
	if st&ua.StatusCodeHistorianMultiValue != 0 {
		parts = append(parts, "MultipleValues")
	}
	return strings.Join(parts, ", ")
}

// normStatus sorts the flags of a status of the file: it writes "Partial,
// MultipleValues" once in the other order.
func normStatus(s string) string {
	parts := strings.Split(s, ", ")
	var flags []string
	order := []string{"Calculated", "Interpolated", "Partial", "MultipleValues"}
	for _, o := range order {
		for _, p := range parts[1:] {
			if p == o {
				flags = append(flags, p)
			}
		}
	}
	return strings.Join(append(parts[:1:1], flags...), ", ")
}

// valueMatches compares a value of the file with a processed value: a
// number to the precision it is written with, a StatusCode by its symbol.
func valueMatches(want string, got *ua.Variant) bool {
	if want == "" {
		return got == nil
	}
	if got == nil {
		return false
	}
	if st, ok := got.Value().(ua.StatusCode); ok {
		return strings.TrimPrefix(st.Symbol(), "Status") == want
	}
	w, err := strconv.ParseFloat(want, 64)
	if err != nil {
		return false
	}
	g, ok := number(got)
	if !ok {
		return false
	}
	decimals := 0
	if i := strings.IndexByte(want, '.'); i >= 0 {
		decimals = len(want) - i - 1
	}
	return math.Abs(g-w) <= 0.5*math.Pow(10, -float64(decimals))+1e-9
}

func valueText(v *ua.Variant) string {
	if v == nil {
		return ""
	}
	if st, ok := v.Value().(ua.StatusCode); ok {
		return strings.TrimPrefix(st.Symbol(), "Status")
	}
	return fmt.Sprint(v.Value())
}

// annexDeviation is an expected result of the file this package does not
// return because a clause of Part 13 says otherwise; value and status are
// what the clause gives.
type annexDeviation struct {
	value, status string
	why           string
}

func annexKey(agg, historian string, ts time.Time) string {
	return agg + "/" + historian + "/" + ts.Format("15:04:05.000")
}

// TestAnnexExamples calculates every processed table of Annex A from its
// raw data set and configuration and compares each value, timestamp and
// StatusCode with the file. Results the package gives differently because
// a clause of Part 13 says so are listed in annexDeviations with the
// clause; they are checked too.
func TestAnnexExamples(t *testing.T) {
	af := loadAnnex(t)
	if len(af.raw) != 5 || len(af.tables) == 0 {
		t.Fatalf("annex: %d raw data sets, %d tables", len(af.raw), len(af.tables))
	}
	start := annexDay.Add(12 * time.Hour)
	end := start.Add(100 * time.Second)
	var rows, deviated int
	used := map[string]bool{}
	for _, tb := range af.tables {
		f := functionByName(tb.aggregate)
		if f == nil {
			if tb.aggregate != "AnnotationCount" {
				t.Errorf("annex: no Aggregate %s", tb.aggregate)
			}
			continue
		}
		req := Request{Aggregate: ua.NewNumericNodeID(0, f.id), Start: start, End: end, ProcessingInterval: tb.pi, Config: tb.cfg}
		got, st := req.Calculate(af.raw[tb.historian])
		if st != ua.StatusOK {
			t.Errorf("%s/%s: %v", tb.aggregate, tb.historian, st)
			continue
		}
		if len(got) != len(tb.rows) {
			t.Errorf("%s/%s: %d values, want %d", tb.aggregate, tb.historian, len(got), len(tb.rows))
			continue
		}
		for i, row := range tb.rows {
			rows++
			want := annexDeviation{value: row.value, status: normStatus(row.status)}
			key := annexKey(tb.aggregate, tb.historian, row.ts)
			if d, ok := annexDeviations[key]; ok {
				want, deviated = d, deviated+1
				used[key] = true
			}
			dv := got[i]
			if !dv.SourceTimestamp.Equal(row.ts) || !valueMatches(want.value, dv.Value) || statusText(dv.Status) != want.status {
				t.Errorf("%s: got %s %q %q, want %s %q %q", key,
					dv.SourceTimestamp.Format("15:04:05.000"), valueText(dv.Value), statusText(dv.Status),
					row.ts.Format("15:04:05.000"), want.value, want.status)
			}
		}
	}
	for key := range annexDeviations {
		if !used[key] {
			t.Errorf("annex deviation %s matches no row", key)
		}
	}
	t.Logf("annex: %d rows of %d tables, %d by a clause rather than the file", rows, len(af.tables), deviated)
}

func functionByName(name string) *function {
	for _, f := range functions {
		if f.name == name {
			return f
		}
	}
	return nil
}
