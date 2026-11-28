// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"testing"

	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/ua"
)

// TestNotPersisted: only 0:NotPersisted with the Boolean TRUE (Part 14
// §6.2.2 Table 4) keeps a component out of the store.
func TestNotPersisted(t *testing.T) {
	t.Parallel()
	key := func(ns uint16) *ua.QualifiedName { return &ua.QualifiedName{NamespaceIndex: ns, Name: "NotPersisted"} }
	for _, tc := range []struct {
		name  string
		props []*ua.KeyValuePair
		want  bool
	}{
		{"absent", nil, false},
		{"TRUE", []*ua.KeyValuePair{{Key: key(0), Value: ua.MustVariant(true)}}, true},
		{"FALSE", []*ua.KeyValuePair{{Key: key(0), Value: ua.MustVariant(false)}}, false},
		{"not a Boolean", []*ua.KeyValuePair{{Key: key(0), Value: ua.MustVariant(int32(1))}}, false},
		{"no value", []*ua.KeyValuePair{{Key: key(0)}}, false},
		{"another namespace", []*ua.KeyValuePair{{Key: key(1), Value: ua.MustVariant(true)}}, false},
		{"nil pair and key", []*ua.KeyValuePair{nil, {Value: ua.MustVariant(true)}, {Key: key(0), Value: ua.MustVariant(true)}}, true},
	} {
		if got := notPersisted(tc.props); got != tc.want {
			t.Errorf("%s: notPersisted = %v; want %v", tc.name, got, tc.want)
		}
	}
}

// fakeStore holds a configuration in memory and fails its writes on
// demand.
type fakeStore struct {
	cfg  *ua.PubSubConfigurationDataType
	fail error
}

func (f *fakeStore) LoadPubSubConfiguration(context.Context, []string) (*ua.PubSubConfigurationDataType, error) {
	return f.cfg, nil
}

func (f *fakeStore) StorePubSubConfiguration(_ context.Context, cfg *ua.PubSubConfigurationDataType, _ []string) error {
	if f.fail != nil {
		return f.fail
	}
	f.cfg = cfg
	return nil
}

// TestPubSubStoreReconcileFails: when the runtime cannot be brought to the
// stored configuration the restore fails and is tried again; when it
// cannot be brought back after a write the store refused, the change fails
// all the same. Not parallel: it replaces reconcileTo.
func TestPubSubStoreReconcileFails(t *testing.T) {
	boom := errors.New("boom")
	failing := func(*pubsub.PubSub, *ua.PubSubConfigurationDataType) error { return boom }
	defer func() { reconcileTo = reconcilePubSub }()

	st := &fakeStore{cfg: pubsub.NewConfiguration(nil, pubsub.UDPConnection("C", "opc.udp://239.0.0.1:4840", 1))}
	s, err := New(EndPoint("localhost", 0), InsecureNoSecurity(), WithPubSub(nil), WithPubSubStore(st))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	reconcileTo = failing
	if err := s.BuildPubSubModel(); !errors.Is(err, boom) {
		t.Fatalf("BuildPubSubModel = %v; want %v", err, boom)
	}
	reconcileTo = reconcilePubSub
	if err := s.BuildPubSubModel(); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.PubSub().Lookup(pubsub.KindConnection, pubsub.Root, "C"); !ok {
		t.Fatal("not restored")
	}

	st.fail = ua.StatusBadResourceUnavailable
	reconcileTo = failing
	err = s.ChangePubSubConfiguration(func(rt *pubsub.PubSub) error {
		_, err := rt.AddConnection(pubsub.UDPConnection("D", "opc.udp://239.0.0.1:4840", 2))
		return err
	})
	if !errors.Is(err, ua.StatusBadInternalError) {
		t.Fatalf("ChangePubSubConfiguration = %v; want Bad_InternalError", err)
	}
}
