// SPDX-License-Identifier: MIT

package fxcm

import (
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
)

// LockOwner identifies the holder of the Lock of a set in edit: a client
// session for EditConnectionConfigurationSets (§6.7.4), or what an
// application chooses. The empty LockOwner is not an owner.
type LockOwner string

// EditSlot is the edit state of one editable set (§6.7.4): at most one
// Edit, owned by the holder of the Lock. The zero EditSlot is a set that is
// not in edit, with the Lock at the ConnectionManager (F.1.3). An EditSlot
// is not safe for concurrent use: the ConnectionManager serializes the
// calls on a set.
type EditSlot struct {
	edit *Edit
}

// Edit is the working copy of a set in edit. The updates are processed only
// after Commit (§6.7.4).
type Edit struct {
	base  *Config
	owner LockOwner
	work  *uafx.ConnectionConfigurationSetConf
}

// Owner returns the holder of the Lock.
func (e *Edit) Owner() LockOwner { return e.owner }

// Base returns the Config the edit started from.
func (e *Edit) Base() *Config { return e.base }

// Conf returns the working copy, for the owner to change. It is the same
// value on every call.
func (e *Edit) Conf() *uafx.ConnectionConfigurationSetConf { return e.work }

// Editing returns the Edit in progress, nil when the set is not in edit
// (Edit FALSE).
func (s *EditSlot) Editing() *Edit { return s.edit }

// Start is StartEditing (§6.7.4): the set goes into edit with the Lock
// given to owner and a working copy of cur. When owner already holds the
// Lock, nothing changes and Start returns the Edit in progress. Another
// owner's edit is ua.StatusBadInvalidState (Table 82).
func (s *EditSlot) Start(cur *Config, owner LockOwner) (*Edit, error) {
	if owner == "" {
		return nil, managerError(ua.StatusBadInvalidArgument, "no LockOwner")
	}
	if s.edit != nil {
		if s.edit.owner == owner {
			return s.edit, nil
		}
		return nil, managerError(ua.StatusBadInvalidState, "the set %s is locked by another client", cur.key)
	}
	s.edit = &Edit{base: cur, owner: owner, work: cur.Conf()}
	return s.edit, nil
}

// Commit is CommitUpdates (§6.7.4): the working copy becomes the next
// Version of the set (Version is incremented on every commit, §6.7.4 and
// §6.8.2) and the Lock goes back to the ConnectionManager. ok is false when
// the set is not in edit: the call is ignored for the set and cfg is nil.
// The caller must hold the Lock, else ua.StatusBadInvalidState (Table 82).
//
// Library interpretation: an invalid working copy, or one whose BrowseName
// or Folder changed (the identity of the set, §6.7.2; renaming is a
// Replace, F.3.3.2), is a *ConfigError and the set stays in edit with the
// Lock at the owner, who may correct or discard it.
func (s *EditSlot) Commit(owner LockOwner) (cfg *Config, ok bool, err error) {
	e := s.edit
	switch {
	case e == nil:
		return nil, false, nil
	case e.owner != owner:
		return nil, false, managerError(ua.StatusBadInvalidState, "the set %s is locked by another client", e.base.key)
	}
	if k := KeyOf(e.work); !k.Equal(e.base.key) {
		return nil, false, &ConfigError{Key: e.base.key, Findings: []Finding{{
			Path: "BrowseName", Clause: libInterp + ": §6.7.2, F.3.3.2",
			Problem: "the edit renames the set to " + k.String() + ": a new name is a Replace",
		}}}
	}
	cfg, err = newConfig(e.work, e.base.version+1)
	if err != nil {
		return nil, false, err
	}
	s.edit = nil
	return cfg, true, nil
}

// Discard is DiscardUpdates (§6.7.4): the updates are dropped and the Lock
// goes back to the ConnectionManager. ok is false when the set is not in
// edit: the call is ignored for the set. The caller must hold the Lock,
// else ua.StatusBadInvalidState (Table 82).
func (s *EditSlot) Discard(owner LockOwner) (ok bool, err error) {
	switch {
	case s.edit == nil:
		return false, nil
	case s.edit.owner != owner:
		return false, managerError(ua.StatusBadInvalidState, "the set %s is locked by another client", s.edit.base.key)
	}
	s.edit = nil
	return true, nil
}

// LockLost ends the edit when its Lock goes for any reason, such as the end
// of the owner's session or an expired Lock: the set is treated as
// DiscardUpdates (§6.7.4). It reports whether an edit ended.
func (s *EditSlot) LockLost() bool {
	ok := s.edit != nil
	s.edit = nil
	return ok
}

// EndpointRef names an endpoint configuration of a set: the name of its
// Connection and 1 or 2.
type EndpointRef struct {
	Connection string
	Endpoint   int
}

// Renamed returns the endpoints of old whose Name next changes, in the
// order of old. A ConnectionManager rejects such a change while the
// Connection is established (§6.12: the Name is needed to close the
// Connection); which Connections are established is the engine's state.
func Renamed(old, next *Config) []EndpointRef {
	names := map[EndpointRef]string{}
	for _, cn := range next.conns {
		for _, e := range cn.endpoints {
			names[EndpointRef{cn.name, e.number}] = e.conf.Name
		}
	}
	var out []EndpointRef
	for _, cn := range old.conns {
		for _, e := range cn.endpoints {
			r := EndpointRef{cn.name, e.number}
			if n, ok := names[r]; ok && n != e.conf.Name {
				out = append(out, r)
			}
		}
	}
	return out
}
