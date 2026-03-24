package id

import "testing"

func TestAggregateType(t *testing.T) {
	tests := []struct {
		name   string
		wantID uint32
	}{
		{"Average", AggregateFunctionAverage},
		{"Minimum", AggregateFunctionMinimum},
		{"Maximum", AggregateFunctionMaximum},
		{"Count", AggregateFunctionCount},
		{"Total", AggregateFunctionTotal},
		{"Interpolative", AggregateFunctionInterpolative},
		{"Start", AggregateFunctionStart},
		{"End", AggregateFunctionEnd},
		{"Delta", AggregateFunctionDelta},
		{"Range", AggregateFunctionRange},
		{"PercentGood", AggregateFunctionPercentGood},
		{"PercentBad", AggregateFunctionPercentBad},
		{"DurationGood", AggregateFunctionDurationGood},
		{"DurationBad", AggregateFunctionDurationBad},
		{"WorstQuality", AggregateFunctionWorstQuality},
		{"TimeAverage", AggregateFunctionTimeAverage},
		{"AnnotationCount", AggregateFunctionAnnotationCount},
		{"MinimumActualTime", AggregateFunctionMinimumActualTime},
		{"MaximumActualTime", AggregateFunctionMaximumActualTime},
		{"NumberOfTransitions", AggregateFunctionNumberOfTransitions},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := AggregateType(tt.name)
			if !ok {
				t.Fatalf("AggregateType(%q) returned false", tt.name)
			}
			if got != tt.wantID {
				t.Errorf("got %d, want %d", got, tt.wantID)
			}
		})
	}
}

func TestAggregateTypeCaseInsensitive(t *testing.T) {
	tests := []string{"average", "AVERAGE", "Average", "aVeRaGe"}
	for _, name := range tests {
		got, ok := AggregateType(name)
		if !ok {
			t.Fatalf("AggregateType(%q) returned false", name)
		}
		if got != AggregateFunctionAverage {
			t.Errorf("AggregateType(%q): got %d, want %d", name, got, AggregateFunctionAverage)
		}
	}
}

func TestAggregateTypeUnknown(t *testing.T) {
	_, ok := AggregateType("NonExistent")
	if ok {
		t.Error("AggregateType(NonExistent) should return false")
	}
}
