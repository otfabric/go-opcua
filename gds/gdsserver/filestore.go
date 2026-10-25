// SPDX-License-Identifier: MIT

package gdsserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/otfabric/go-opcua/gds"
	"github.com/otfabric/go-opcua/ua"
)

// FileStore is a Store that keeps the state in a directory, one JSON file
// per application, request and certificate authority and one for the
// Meta:
//
//	<dir>/applications/<id>.json
//	<dir>/requests/<id>.json
//	<dir>/issuers/<name>.json
//	<dir>/meta.json
//
// Every file is written to a temporary file in its directory, synced and
// renamed over the old one, so a crash leaves the old or the new version.
// The files hold the private keys of the CAs and the passwords of pending
// new key pair requests: they are created with mode 0600 and the
// directories with 0700. A FileStore may be used by one GDS at a time.
type FileStore struct {
	dir string
	mu  sync.Mutex
}

const (
	dirApplications = "applications"
	dirRequests     = "requests"
	dirIssuers      = "issuers"
	fileMeta        = "meta.json"
	tmpPrefix       = ".tmp-"
)

// NewFileStore returns a FileStore in dir, which it creates if needed.
func NewFileStore(dir string) (*FileStore, error) {
	for _, d := range []string{dir, filepath.Join(dir, dirApplications), filepath.Join(dir, dirRequests), filepath.Join(dir, dirIssuers)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, fmt.Errorf("gdsserver: file store: %w", err)
		}
	}
	return &FileStore{dir: dir}, nil
}

// fileName accepts the IDs and issuer names as file names: letters,
// digits and '-'.
var fileName = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

func (f *FileStore) path(sub, name string) (string, error) {
	if !fileName.MatchString(name) {
		return "", fmt.Errorf("gdsserver: file store: invalid name %q", name)
	}
	return filepath.Join(f.dir, sub, name+".json"), nil
}

// The file formats. The ApplicationRecord is written field by field:
// ua.LocalizedText has no JSON decoding.
type (
	fileText struct {
		Locale string `json:"locale,omitempty"`
		Text   string `json:"text"`
	}
	fileRecord struct {
		ApplicationURI     string             `json:"applicationUri"`
		ApplicationType    ua.ApplicationType `json:"applicationType"`
		ApplicationNames   []fileText         `json:"applicationNames"`
		ProductURI         string             `json:"productUri"`
		DiscoveryURLs      []string           `json:"discoveryUrls,omitempty"`
		ServerCapabilities []string           `json:"serverCapabilities,omitempty"`
	}
	fileApplication struct {
		ID           string               `json:"id"`
		RecordID     uint32               `json:"recordId"`
		Record       *fileRecord          `json:"record"`
		EndpointIDs  []uint32             `json:"endpointIds,omitempty"`
		Certificates []*IssuedCertificate `json:"certificates,omitempty"`
	}
)

func toFile(a *Application) *fileApplication {
	out := &fileApplication{ID: a.ID, RecordID: a.RecordID, EndpointIDs: a.EndpointIDs, Certificates: a.Certificates}
	if r := a.Record; r != nil {
		fr := &fileRecord{ApplicationURI: r.ApplicationURI, ApplicationType: r.ApplicationType, ProductURI: r.ProductURI,
			DiscoveryURLs: r.DiscoveryURLs, ServerCapabilities: r.ServerCapabilities}
		for _, n := range r.ApplicationNames {
			if n != nil {
				fr.ApplicationNames = append(fr.ApplicationNames, fileText{Locale: n.Locale, Text: n.Text})
			}
		}
		out.Record = fr
	}
	return out
}

func fromFile(fa *fileApplication) *Application {
	a := &Application{ID: fa.ID, RecordID: fa.RecordID, EndpointIDs: fa.EndpointIDs, Certificates: fa.Certificates}
	if fr := fa.Record; fr != nil {
		r := &gds.ApplicationRecord{ApplicationURI: fr.ApplicationURI, ApplicationType: fr.ApplicationType, ProductURI: fr.ProductURI,
			DiscoveryURLs: fr.DiscoveryURLs, ServerCapabilities: fr.ServerCapabilities}
		for _, n := range fr.ApplicationNames {
			r.ApplicationNames = append(r.ApplicationNames, ua.NewLocalizedTextWithLocale(n.Text, n.Locale))
		}
		a.Record = r
	}
	return a
}

// writeFile writes v as JSON to path atomically, with mode 0600.
func writeFile(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, tmpPrefix+"*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = tmp.Close()
			_ = os.Remove(name)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	return syncDir(dir)
}

// syncDir makes a rename in dir durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// readDir decodes every JSON file of a subdirectory with decode, in the
// order of the names; temporary files of interrupted writes are removed.
func (f *FileStore) readDir(sub string, decode func([]byte) error) error {
	dir := filepath.Join(f.dir, sub)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, tmpPrefix) {
			_ = os.Remove(filepath.Join(dir, name))
			continue
		}
		if e.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		if err := decode(b); err != nil {
			return fmt.Errorf("%s: %w", filepath.Join(sub, name), err)
		}
	}
	return nil
}

// Load reads the state from the directory.
func (f *FileStore) Load(context.Context) (*State, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := &State{}
	err := f.readDir(dirApplications, func(b []byte) error {
		var fa fileApplication
		if err := json.Unmarshal(b, &fa); err != nil {
			return err
		}
		st.Applications = append(st.Applications, fromFile(&fa))
		return nil
	})
	if err == nil {
		err = f.readDir(dirRequests, func(b []byte) error {
			var r Request
			if err := json.Unmarshal(b, &r); err != nil {
				return err
			}
			st.Requests = append(st.Requests, &r)
			return nil
		})
	}
	if err == nil {
		err = f.readDir(dirIssuers, func(b []byte) error {
			var i Issuer
			if err := json.Unmarshal(b, &i); err != nil {
				return err
			}
			st.Issuers = append(st.Issuers, &i)
			return nil
		})
	}
	if err != nil {
		return nil, fmt.Errorf("gdsserver: file store: %w", err)
	}
	sort.Slice(st.Applications, func(i, j int) bool { return st.Applications[i].RecordID < st.Applications[j].RecordID })
	b, err := os.ReadFile(filepath.Join(f.dir, fileMeta))
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("gdsserver: file store: %w", err)
	default:
		var m Meta
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, fmt.Errorf("gdsserver: file store: %s: %w", fileMeta, err)
		}
		st.Meta = &m
	}
	return st, nil
}

func (f *FileStore) put(sub, name string, v any) error {
	p, err := f.path(sub, name)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := writeFile(p, v); err != nil {
		return fmt.Errorf("gdsserver: file store: %w", err)
	}
	return nil
}

func (f *FileStore) remove(sub, name string) error {
	p, err := f.path(sub, name)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("gdsserver: file store: %w", err)
	}
	return syncDir(filepath.Dir(p))
}

// PutApplication writes the file of the application.
func (f *FileStore) PutApplication(_ context.Context, app *Application) error {
	return f.put(dirApplications, app.ID, toFile(app))
}

// DeleteApplication removes the file of the application.
func (f *FileStore) DeleteApplication(_ context.Context, id string) error {
	return f.remove(dirApplications, id)
}

// PutRequest writes the file of the request.
func (f *FileStore) PutRequest(_ context.Context, req *Request) error {
	return f.put(dirRequests, req.ID, req)
}

// DeleteRequest removes the file of the request.
func (f *FileStore) DeleteRequest(_ context.Context, id string) error {
	return f.remove(dirRequests, id)
}

// PutIssuer writes the file of the certificate authority.
func (f *FileStore) PutIssuer(_ context.Context, iss *Issuer) error {
	return f.put(dirIssuers, iss.Name, iss)
}

// PutMeta writes meta.json.
func (f *FileStore) PutMeta(_ context.Context, meta *Meta) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := writeFile(filepath.Join(f.dir, fileMeta), meta); err != nil {
		return fmt.Errorf("gdsserver: file store: %w", err)
	}
	return nil
}
