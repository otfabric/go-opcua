// SPDX-License-Identifier: MIT

package aggregate

import "github.com/otfabric/go-opcua/ua"

// Config is the configuration an Aggregate is calculated with: the
// Properties of the AggregateConfigurationType (Part 13 §4.2.1.2) and the
// Stepped Property of the HistoricalDataConfigurationType of the Variable
// (Part 11 §5.2.2).
type Config struct {
	// TreatUncertainAsBad: "A value of True indicates the Server considers
	// the severity equivalent to Bad, a value of False indicates the Server
	// considers the severity equivalent to Good, unless the Aggregate
	// definition says otherwise" (Part 13 §4.2.1.2).
	TreatUncertainAsBad bool
	// PercentDataBad is "the minimum percentage of Bad data in a given
	// interval required for the StatusCode for the given interval for
	// processed data request to be set to Bad" (Part 13 §4.2.1.2).
	PercentDataBad uint8
	// PercentDataGood is "the minimum percentage of Good data in a given
	// interval required for the StatusCode for the given interval for the
	// processed data requests to be set to Good" (Part 13 §4.2.1.2).
	PercentDataGood uint8
	// UseSlopedExtrapolation selects SlopedExtrapolation over
	// SteppedExtrapolation where an Interpolated Bounding Value has no value
	// after it (Part 13 §4.2.1.2, §3.1.8). "For SimpleBounds this value is
	// ignored."
	UseSlopedExtrapolation bool
	// Stepped is the Stepped Property of the Variable: True for
	// SteppedInterpolation, False for SlopedInterpolation (Part 11 §5.2.2).
	// It changes the Aggregates that use Simple Bounding Values and the
	// time weighted ones that follow it (TimeAverage2, Total2, ...).
	Stepped bool
}

// DefaultConfig is the default configuration: "The default value is True"
// for TreatUncertainAsBad, 100 for PercentDataBad and PercentDataGood,
// False for UseSlopedExtrapolation (Part 13 §4.2.1.2), and False for
// Stepped (Part 11 §5.2.2).
func DefaultConfig() Config {
	return Config{TreatUncertainAsBad: true, PercentDataBad: 100, PercentDataGood: 100}
}

// Valid reports whether the percentages give a valid calculation: "The
// PercentDataGood and PercentDataBad shall follow the following
// relationship PercentDataGood ≥ (100 - PercentDataBad)" and neither may
// exceed 100 (Part 13 §4.2.1.2). A configuration that is not valid gives
// Bad_AggregateInvalidInputs.
func (c Config) Valid() bool {
	return c.PercentDataGood <= 100 && c.PercentDataBad <= 100 && int(c.PercentDataGood) >= 100-int(c.PercentDataBad)
}

// Override returns the configuration a request asks for: the
// aggregateConfiguration of ReadProcessedDetails (Part 11 §6.5.4.1) or of an
// AggregateFilter (Part 4 §7.22.4) "allows Clients to override the
// Aggregate configuration settings supplied by the AggregateConfiguration
// Object". With useServerCapabilitiesDefaults, or without a configuration,
// c (the configuration of the Variable or of the Server) is used and "any
// values specified for the other parameters are ignored" (Part 13 §5.2.2).
// Stepped is a Property of the Variable and is kept.
//
// A configuration with every field zero or false is read as no override:
// it is what a client that leaves the structure unset encodes, and as an
// override it is not valid (PercentDataGood 0 < 100 - PercentDataBad 0)
// and would make every interval Bad_AggregateInvalidInputs. UA-.NETStandard
// reads it the same way.
func (c Config) Override(ac *ua.AggregateConfiguration) Config {
	if ac == nil || ac.UseServerCapabilitiesDefaults || *ac == (ua.AggregateConfiguration{}) {
		return c
	}
	return Config{
		TreatUncertainAsBad:    ac.TreatUncertainAsBad,
		PercentDataBad:         ac.PercentDataBad,
		PercentDataGood:        ac.PercentDataGood,
		UseSlopedExtrapolation: ac.UseSlopedExtrapolation,
		Stepped:                c.Stepped,
	}
}

// AggregateConfiguration returns c as the structure of the services, with
// useServerCapabilitiesDefaults false.
func (c Config) AggregateConfiguration() *ua.AggregateConfiguration {
	return &ua.AggregateConfiguration{
		TreatUncertainAsBad:    c.TreatUncertainAsBad,
		PercentDataBad:         c.PercentDataBad,
		PercentDataGood:        c.PercentDataGood,
		UseSlopedExtrapolation: c.UseSlopedExtrapolation,
	}
}
