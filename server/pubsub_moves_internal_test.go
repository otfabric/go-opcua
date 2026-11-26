// SPDX-License-Identifier: MIT

package server

import (
	"testing"

	"github.com/otfabric/go-opcua/pubsub"
)

// TestUnderRemoved: a removed PubSubConnection or group covers what is
// below it, a removed PublishedDataSet only itself (its Name is no
// PubSubConnection's), and nothing else.
func TestUnderRemoved(t *testing.T) {
	t.Parallel()
	conn := configPath{kind: pubsub.KindConnection, names: []string{"C"}}
	group := configPath{kind: pubsub.KindWriterGroup, names: []string{"C", "G"}}
	pds := configPath{kind: pubsub.KindPublishedDataSet, names: []string{"C"}}
	at := func(kind pubsub.ComponentKind, names ...string) componentAt {
		return componentAt{kind: kind, names: names}
	}
	for _, tc := range []struct {
		name    string
		c       componentAt
		removed []configPath
		want    bool
	}{
		{"nothing removed", at(pubsub.KindDataSetWriter, "C", "G", "W"), nil, false},
		{"under a removed connection", at(pubsub.KindDataSetWriter, "C", "G", "W"), []configPath{conn}, true},
		{"the removed connection", at(pubsub.KindConnection, "C"), []configPath{conn}, true},
		{"under a removed group", at(pubsub.KindDataSetWriter, "C", "G", "W"), []configPath{group}, true},
		{"another group", at(pubsub.KindDataSetWriter, "C", "H", "W"), []configPath{group}, false},
		{"the removed data set", at(pubsub.KindPublishedDataSet, "C"), []configPath{pds}, true},
		{"a connection named like a removed data set", at(pubsub.KindConnection, "C"), []configPath{pds}, false},
		{"a data set named like a removed connection", at(pubsub.KindPublishedDataSet, "C"), []configPath{conn}, false},
	} {
		if got := underRemoved(tc.c, tc.removed); got != tc.want {
			t.Errorf("%s: underRemoved = %v; want %v", tc.name, got, tc.want)
		}
	}
	before := map[string]componentAt{"k": {id: 1, kind: pubsub.KindConnection, names: []string{"C"}}, "same": {id: 3}}
	after := map[string]componentAt{"k": {id: 2, kind: pubsub.KindConnection, names: []string{"C"}}, "same": {id: 3}, "new": {id: 4}}
	if m := movesBetween(before, after, nil); len(m) != 1 || m[0].From != 1 || m[0].To != 2 {
		t.Errorf("movesBetween = %+v; want 1 -> 2 only", m)
	}
	if m := movesBetween(before, after, []configPath{conn}); len(m) != 0 {
		t.Errorf("movesBetween with C removed = %+v; want none", m)
	}
}
