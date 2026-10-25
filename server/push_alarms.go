// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uapolicy"
)

// The alarms of the certificate groups (Part 12 §7.8.3): CertificateExpired
// (CertificateExpirationAlarmType, Part 12 §7.8.5) and TrustListOutOfDate
// (TrustListOutOfDateAlarmType, Part 12 §7.8.6), conditions of the Alarms &
// Conditions model of the server with their group as source node.

// Severities of the certificate alarms.
const (
	severityCertInactive = 100
	severityCertExpiring = 500
	severityCertExpired  = 900
	severityTrustListOld = 500
)

// expiryAlarm is the CertificateExpired alarm of a group.
type expiryAlarm struct {
	g    *certGroup
	cond *Condition

	// The values of the properties; certAlarms.propMu.
	date     time.Time
	certType uint32
	cert     []byte

	// The state last reported; certAlarms.evalMu.
	active, expired bool
}

// outOfDateAlarm is the TrustListOutOfDate alarm of a group.
type outOfDateAlarm struct {
	g    *certGroup
	cond *Condition

	last time.Time // certAlarms.propMu

	active bool // certAlarms.evalMu
}

// certAlarms evaluates the alarms of the certificate groups.
type certAlarms struct {
	m   *pushManager
	cfg CertificateAlarms

	expiry    []*expiryAlarm
	outOfDate []*outOfDateAlarm

	// evalMu serializes the evaluations; propMu guards the values of the
	// properties, which the conditions read with their lock held.
	evalMu sync.Mutex
	propMu sync.Mutex

	kickc  chan struct{}
	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// buildAlarms adds the alarms to the certificate groups.
func (m *pushManager) buildAlarms() error {
	s := m.s
	var ns *NodeNameSpace
	for _, x := range s.Namespaces() {
		if nns, ok := x.(*NodeNameSpace); ok && x.Name() == CertificateAlarmsNamespaceURI {
			ns = nns
		}
	}
	if ns == nil {
		ns = NewNodeNameSpace(s, CertificateAlarmsNamespaceURI)
	}
	a := &certAlarms{m: m, cfg: *m.cfg.Alarms, kickc: make(chan struct{}, 1)}
	class := ua.NewNumericNodeID(0, id.SystemConditionClassType)
	for _, g := range m.groups {
		if g.kind != groupUserToken {
			x := &expiryAlarm{g: g}
			cond, err := s.AddCondition(ConditionConfig{
				Type:             ua.NewNumericNodeID(0, id.CertificateExpirationAlarmType),
				Namespace:        ns,
				Name:             "CertificateExpired",
				Source:           g.nodeID(),
				SourceName:       g.def.name,
				ConditionClassID: class,
				Severity:         severityCertInactive,
				Properties: []ConditionProperty{
					{Name: "ExpirationDate", DataType: id.UtcTime, Value: a.prop(func() any { return x.date.UTC() })},
					{Name: "ExpirationLimit", DataType: id.Duration, Value: func() any { return float64(a.cfg.ExpirationLimit) / float64(time.Millisecond) }},
					{Name: "CertificateType", DataType: id.NodeID, Value: a.prop(func() any { return nullNodeID(transitionNodeID(x.certType)) })},
					{Name: "Certificate", DataType: id.ByteString, Value: a.prop(func() any { return slices.Clone(x.cert) })},
				},
			})
			if err != nil {
				return err
			}
			x.cond = cond
			a.expiry = append(a.expiry, x)
			standardBrowseName(s, cond, "CertificateExpired")
		}
		x := &outOfDateAlarm{g: g}
		cond, err := s.AddCondition(ConditionConfig{
			Type:             ua.NewNumericNodeID(0, id.TrustListOutOfDateAlarmType),
			Namespace:        ns,
			Name:             "TrustListOutOfDate",
			Source:           g.nodeID(),
			SourceName:       g.def.name,
			ConditionClassID: class,
			Severity:         severityCertInactive,
			Properties: []ConditionProperty{
				{Name: "TrustListId", DataType: id.NodeID, Value: func() any { return g.trustListID() }},
				{Name: "LastUpdateTime", DataType: id.UtcTime, Value: a.prop(func() any { return x.last.UTC() })},
				{Name: "UpdateFrequency", DataType: id.Duration, Value: func() any {
					return float64(m.cfg.TrustListUpdateFrequency) / float64(time.Millisecond)
				}},
			},
		})
		if err != nil {
			return err
		}
		x.cond = cond
		a.outOfDate = append(a.outOfDate, x)
		standardBrowseName(s, cond, "TrustListOutOfDate")
	}
	m.alarms = a
	a.evaluate()
	return nil
}

// standardBrowseName gives the condition the BrowseName of the component
// of CertificateGroupType in namespace 0.
func standardBrowseName(s *Server, c *Condition, name string) {
	if n := s.Node(c.NodeID()); n != nil {
		_ = n.SetAttribute(ua.AttributeIDBrowseName, DataValueFromValue(&ua.QualifiedName{Name: name}))
	}
}

// prop wraps the value of a property with propMu.
func (a *certAlarms) prop(f func() any) func() any {
	return func() any {
		a.propMu.Lock()
		defer a.propMu.Unlock()
		return f()
	}
}

// evaluateAlarms has the alarms evaluated after a change of the
// certificates or trust lists. The evaluation runs in the goroutine of
// the alarms, which does not need the locks of the caller.
func (m *pushManager) evaluateAlarms() {
	if m.alarms != nil {
		m.alarms.kick()
	}
}

func (a *certAlarms) kick() {
	select {
	case a.kickc <- struct{}{}:
	default: // an evaluation is pending, which sees this change too
	}
}

// start starts the evaluations every CheckInterval and on kick.
func (a *certAlarms) start() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel, a.done = cancel, make(chan struct{})
	go a.run(ctx, a.done)
}

// stop stops the evaluations and waits for the one running.
func (a *certAlarms) stop() {
	a.mu.Lock()
	cancel, done := a.cancel, a.done
	a.cancel, a.done = nil, nil
	a.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

func (a *certAlarms) run(ctx context.Context, done chan struct{}) {
	defer close(done)
	t := time.NewTicker(a.cfg.CheckInterval)
	defer t.Stop()
	a.evaluate()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-a.kickc:
		}
		a.evaluate()
	}
}

// evaluate brings the alarms up to date with the certificates, the trust
// lists and the clock.
func (a *certAlarms) evaluate() {
	a.evalMu.Lock()
	defer a.evalMu.Unlock()
	now := a.m.now()
	for _, x := range a.expiry {
		a.evaluateExpiry(x, now)
	}
	for _, x := range a.outOfDate {
		a.evaluateOutOfDate(x, now)
	}
}

// evaluateExpiry evaluates the CertificateExpired alarm of a group for the
// certificate of the group that expires first.
func (a *certAlarms) evaluateExpiry(x *expiryAlarm, now time.Time) {
	types, certs := a.m.groupCerts(x.g)
	var (
		date     time.Time
		certType uint32
		cert     []byte
	)
	for i, c := range certs {
		pc, err := uapolicy.ParseCertificate(c.certificate)
		if err != nil {
			continue
		}
		if cert == nil || pc.NotAfter.Before(date) {
			date, certType, cert = pc.NotAfter, types[i], c.certificate
		}
	}
	active := cert != nil && !now.Before(date.Add(-a.cfg.ExpirationLimit))
	expired := cert != nil && now.After(date)

	a.propMu.Lock()
	changed := !x.date.Equal(date) || x.certType != certType || string(x.cert) != string(cert)
	x.date, x.certType, x.cert = date, certType, cert
	a.propMu.Unlock()
	if !changed && active == x.active && expired == x.expired {
		return
	}
	x.active, x.expired = active, expired
	sev := uint16(severityCertInactive)
	msg := "The certificates of the group are valid"
	switch {
	case expired:
		sev, msg = severityCertExpired, fmt.Sprintf("A certificate of the group expired at %s", date.UTC().Format(time.RFC3339))
	case active:
		sev, msg = severityCertExpiring, fmt.Sprintf("A certificate of the group expires at %s", date.UTC().Format(time.RFC3339))
	case cert == nil:
		msg = "The group has no certificate"
	}
	a.update(x.cond, active, sev, msg)
}

// evaluateOutOfDate evaluates the TrustListOutOfDate alarm of a group: the
// trust list is out of date when it has not been updated for
// UpdateFrequency.
func (a *certAlarms) evaluateOutOfDate(x *outOfDateAlarm, now time.Time) {
	last := time.Unix(0, x.g.lastUpdate.Load())
	freq := a.m.cfg.TrustListUpdateFrequency
	active := freq > 0 && now.After(last.Add(freq))

	a.propMu.Lock()
	changed := !x.last.Equal(last)
	x.last = last
	a.propMu.Unlock()
	if !changed && active == x.active {
		return
	}
	x.active = active
	sev, msg := uint16(severityCertInactive), "The trust list is up to date"
	if active {
		sev, msg = severityTrustListOld, fmt.Sprintf("The trust list was last updated at %s", last.UTC().Format(time.RFC3339))
	}
	a.update(x.cond, active, sev, msg)
}

func (a *certAlarms) update(c *Condition, active bool, sev uint16, msg string) {
	if err := c.Update(ConditionUpdate{Active: &active, Severity: &sev, Message: &msg}); err != nil {
		a.m.logger().Debug("push management: certificate alarm not updated", "condition", c.Name(), "error", err)
	}
}
