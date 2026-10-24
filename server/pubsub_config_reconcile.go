// SPDX-License-Identifier: MIT

package server

import (
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/ua"
)

// reconcilePubSub brings the runtime to configuration want with the fewest
// changes: a component whose own parameters differ is removed and added
// again with its children, one that is the same keeps running, and the
// children of it are compared in turn.
func reconcilePubSub(rt *pubsub.PubSub, want *ua.PubSubConfigurationDataType) error {
	have := rt.Configuration()
	for _, d := range have.PublishedDataSets {
		if w := pdsNamed(want, d.Name); w == nil || !sameEncoding(d, w) {
			if id, ok := rt.Lookup(pubsub.KindPublishedDataSet, pubsub.Root, d.Name); ok {
				// This removes the writers of the data set too; they are
				// added again below.
				if err := rt.RemovePublishedDataSet(id); err != nil {
					return err
				}
			}
		}
	}
	have = rt.Configuration()
	for _, w := range want.PublishedDataSets {
		if pdsNamed(have, w.Name) == nil {
			if _, err := rt.AddPublishedDataSet(w); err != nil {
				return err
			}
		}
	}

	have = rt.Configuration()
	for _, c := range have.Connections {
		cid, ok := rt.Lookup(pubsub.KindConnection, pubsub.Root, c.Name)
		if !ok {
			continue
		}
		w := connNamed(want, c.Name)
		if w == nil || !sameEncoding(connOwn(c), connOwn(w)) {
			if err := rt.RemoveConnection(cid); err != nil {
				return err
			}
			continue
		}
		if err := removeChangedGroups(rt, cid, c, w); err != nil {
			return err
		}
	}
	have = rt.Configuration()
	for _, w := range want.Connections {
		c := connNamed(have, w.Name)
		if c == nil {
			if _, err := rt.AddConnection(w); err != nil {
				return err
			}
			continue
		}
		cid, _ := rt.Lookup(pubsub.KindConnection, pubsub.Root, c.Name)
		if err := addMissingGroups(rt, cid, c, w); err != nil {
			return err
		}
	}
	return nil
}

func removeChangedGroups(rt *pubsub.PubSub, cid pubsub.ComponentID, c, w *ua.PubSubConnectionDataType) error {
	for _, g := range c.WriterGroups {
		gid, ok := rt.Lookup(pubsub.KindWriterGroup, cid, g.Name)
		if !ok {
			continue
		}
		wg := writerGroupNamed(w, g.Name)
		if wg == nil || !sameEncoding(writerGroupOwn(g), writerGroupOwn(wg)) {
			if err := rt.RemoveWriterGroup(gid); err != nil {
				return err
			}
			continue
		}
		for _, x := range g.DataSetWriters {
			if y := writerNamed(wg, x.Name); y == nil || !sameEncoding(x, y) {
				if id, ok := rt.Lookup(pubsub.KindDataSetWriter, gid, x.Name); ok {
					if err := rt.RemoveDataSetWriter(id); err != nil {
						return err
					}
				}
			}
		}
	}
	for _, g := range c.ReaderGroups {
		gid, ok := rt.Lookup(pubsub.KindReaderGroup, cid, g.Name)
		if !ok {
			continue
		}
		rg := readerGroupNamed(w, g.Name)
		if rg == nil || !sameEncoding(readerGroupOwn(g), readerGroupOwn(rg)) {
			if err := rt.RemoveReaderGroup(gid); err != nil {
				return err
			}
			continue
		}
		for _, x := range g.DataSetReaders {
			if y := readerNamed(rg, x.Name); y == nil || !sameEncoding(x, y) {
				if id, ok := rt.Lookup(pubsub.KindDataSetReader, gid, x.Name); ok {
					if err := rt.RemoveDataSetReader(id); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func addMissingGroups(rt *pubsub.PubSub, cid pubsub.ComponentID, c, w *ua.PubSubConnectionDataType) error {
	for _, wg := range w.WriterGroups {
		g := writerGroupNamed(c, wg.Name)
		if g == nil {
			if _, err := rt.AddWriterGroup(cid, wg); err != nil {
				return err
			}
			continue
		}
		gid, _ := rt.Lookup(pubsub.KindWriterGroup, cid, g.Name)
		for _, y := range wg.DataSetWriters {
			if writerNamed(g, y.Name) == nil {
				if _, err := rt.AddDataSetWriter(gid, y); err != nil {
					return err
				}
			}
		}
	}
	for _, rg := range w.ReaderGroups {
		g := readerGroupNamed(c, rg.Name)
		if g == nil {
			if _, err := rt.AddReaderGroup(cid, rg); err != nil {
				return err
			}
			continue
		}
		gid, _ := rt.Lookup(pubsub.KindReaderGroup, cid, g.Name)
		for _, y := range rg.DataSetReaders {
			if readerNamed(g, y.Name) == nil {
				if _, err := rt.AddDataSetReader(gid, y); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// connOwn, writerGroupOwn and readerGroupOwn are the parameters of a
// component without its children.
func connOwn(c *ua.PubSubConnectionDataType) *ua.PubSubConnectionDataType {
	x := *c
	x.WriterGroups, x.ReaderGroups = nil, nil
	return &x
}

func writerGroupOwn(g *ua.WriterGroupDataType) *ua.WriterGroupDataType {
	x := *g
	x.DataSetWriters = nil
	return &x
}

func readerGroupOwn(g *ua.ReaderGroupDataType) *ua.ReaderGroupDataType {
	x := *g
	x.DataSetReaders = nil
	return &x
}

func named[T any](xs []*T, n string, nameOf func(*T) string) *T {
	if i := findByName(xs, n, nameOf); i >= 0 {
		return xs[i]
	}
	return nil
}

func pdsNamed(c *ua.PubSubConfigurationDataType, n string) *ua.PublishedDataSetDataType {
	return named(c.PublishedDataSets, n, func(x *ua.PublishedDataSetDataType) string { return x.Name })
}

func connNamed(c *ua.PubSubConfigurationDataType, n string) *ua.PubSubConnectionDataType {
	return named(c.Connections, n, func(x *ua.PubSubConnectionDataType) string { return x.Name })
}

func writerGroupNamed(c *ua.PubSubConnectionDataType, n string) *ua.WriterGroupDataType {
	return named(c.WriterGroups, n, func(x *ua.WriterGroupDataType) string { return x.Name })
}

func readerGroupNamed(c *ua.PubSubConnectionDataType, n string) *ua.ReaderGroupDataType {
	return named(c.ReaderGroups, n, func(x *ua.ReaderGroupDataType) string { return x.Name })
}

func writerNamed(g *ua.WriterGroupDataType, n string) *ua.DataSetWriterDataType {
	return named(g.DataSetWriters, n, func(x *ua.DataSetWriterDataType) string { return x.Name })
}

func readerNamed(g *ua.ReaderGroupDataType, n string) *ua.DataSetReaderDataType {
	return named(g.DataSetReaders, n, func(x *ua.DataSetReaderDataType) string { return x.Name })
}

// nodeOfPath returns the object of the element of a reference, or the null
// NodeId.
func (f *configFile) nodeOfPath(applied bool, p configPath) *ua.NodeID {
	null := ua.NewTwoByteNodeID(0)
	if !applied || len(p.names) == 0 {
		return null
	}
	rt := f.m.rt
	kinds := []pubsub.ComponentKind{pubsub.KindConnection}
	switch p.kind {
	case pubsub.KindPublishedDataSet:
		kinds = []pubsub.ComponentKind{pubsub.KindPublishedDataSet}
	case pubsub.KindWriterGroup, pubsub.KindReaderGroup:
		kinds = append(kinds, p.kind)
	case pubsub.KindDataSetWriter:
		kinds = append(kinds, pubsub.KindWriterGroup, p.kind)
	case pubsub.KindDataSetReader:
		kinds = append(kinds, pubsub.KindReaderGroup, p.kind)
	case pubsub.KindConnection, pubsub.KindPubSub:
	}
	if len(kinds) != len(p.names) {
		return null
	}
	cid := pubsub.Root
	for i, k := range kinds {
		var ok bool
		if cid, ok = rt.Lookup(k, cid, p.names[i]); !ok {
			return null
		}
	}
	if n, ok := f.m.s.PubSubNodeID(cid); ok {
		return n
	}
	return null
}
