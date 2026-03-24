package opcua

import (
	"testing"

	"github.com/otfabric/go-opcua/id"
)

func TestAggregateType(t *testing.T) {
	tests := []struct {
		name   string
		wantID uint32
	}{
		{"Average", id.AggregateFunction_Average},
		{"Minimum", id.AggregateFunction_Minimum},
		{"Maximum", id.AggregateFunction_Maximum},
		{"Count", id.AggregateFunction_Count},
		{"Total", id.AggregateFunction_Total},
		{"Interpolative", id.AggregateFunction_Interpolative},
		{"Start", id.AggregateFunction_Start},
		{"End", id.AggregateFunction_End},
		{"Delta", id.AggregateFunction_Delta},
		{"Range", id.AggregateFunction_Range},
		{"PercentGood", id.AggregateFunction_PercentGood},
		{"PercentBad", id.AggregateFunction_PercentBad},
		{"DurationGood", id.AggregateFunction_DurationGood},
		{"DurationBad", id.AggregateFunction_DurationBad},
		{"WorstQuality", id.AggregateFunction_WorstQuality},
		{"TimeAverage", id.AggregateFunction_TimeAverage},
		{"AnnotationCount", id.AggregateFunction_AnnotationCount},
		{"MinimumActualTime", id.AggregateFunction_MinimumActualTime},
		{"MaximumActualTime", id.AggregateFunction_MaximumActualTime},
		{"NumberOfTransitions", id.AggregateFunction_NumberOfTransitions},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nid := AggregateType(tt.name)
			if nid == nil {
				t.Fatalf("AggregateType(%q) returned nil", tt.name)
			}
			if nid.IntID() != tt.wantID {
				t.Errorf("got %d, want %d", nid.IntID(), tt.wantID)
			}
		})
	}
}

func TestAggregateTypeCaseInsensitive(t *testing.T) {
	tests := []string{"average", "AVERAGE", "Average", "aVeRaGe"}
	for _, name := range tests {
		nid := AggregateType(name)
		if nid == nil {
			t.Fatalf("AggregateType(%q) returned nil", name)
		}
		if nid.IntID() != id.AggregateFunction_Average {
			t.Errorf("AggregateType(%q): got %d, want %d", name, nid.IntID(), id.AggregateFunction_Average)
		}
	}
}

func TestAggregateTypeUnknown(t *testing.T) {
	nid := AggregateType("NonExistent")
	if nid != nil {
		t.Errorf("AggregateType(NonExistent) should return nil, got %v", nid)
	}
}
