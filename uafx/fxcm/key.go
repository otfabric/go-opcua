// SPDX-License-Identifier: MIT

package fxcm

import (
	"slices"
	"strings"

	"github.com/otfabric/go-opcua/uafx"
)

// SetKey is the identity of a ConnectionConfigurationSet: the string part
// of its BrowseName and the path of the Folders that organize it in the
// ConnectionConfigurationSets Folder (§6.7.2, Table F.1
// ConnectionConfigurationSetFolder). The BrowseName is unique within its
// Folder (§6.7.2); F.3.3.2 finds the set an operation replaces or removes by
// both.
type SetKey struct {
	Folder []string
	Name   string
}

// KeyOf returns the SetKey of conf. A null and an empty Folder are the same
// (Table F.1).
func KeyOf(conf *uafx.ConnectionConfigurationSetConf) SetKey {
	if conf == nil {
		return SetKey{}
	}
	k := SetKey{Name: conf.BrowseName}
	if len(conf.ConnectionConfigurationSetFolder) > 0 {
		k.Folder = slices.Clone(conf.ConnectionConfigurationSetFolder)
	}
	return k
}

// Equal reports whether k and o name the same set.
func (k SetKey) Equal(o SetKey) bool {
	return k.Name == o.Name && slices.Equal(k.Folder, o.Folder)
}

// String returns the Folder path and the Name separated by "/", each
// element quoted when it holds a "/" or is empty.
func (k SetKey) String() string {
	parts := make([]string, 0, len(k.Folder)+1)
	for _, p := range append(slices.Clone(k.Folder), k.Name) {
		if p == "" || strings.ContainsAny(p, "/\"") {
			p = `"` + strings.ReplaceAll(p, `"`, `\"`) + `"`
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, "/")
}
