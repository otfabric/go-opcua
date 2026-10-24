// SPDX-License-Identifier: MIT

package remote

import (
	"context"
	"errors"
	"fmt"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// PubSubConfiguration is the PubSubConfiguration file object of the
// PublishSubscribe object (Part 14 §9.1.3.7).
var PubSubConfiguration = ua.NewNumericNodeID(0, id.PublishSubscribePubSubConfiguration)

// configChunk is the size of the Read and Write calls on the file.
const configChunk = 64 << 10

// The modes of FileType.Open used on the file.
const (
	openRead       byte = 0x01
	openWriteErase byte = 0x06
)

func (r *Client) fileCall(ctx context.Context, name string, method uint32, outputs int, args ...*ua.Variant) ([]*ua.Variant, error) {
	return r.call(ctx, PubSubConfiguration, name, method, outputs, args...)
}

func (r *Client) openFile(ctx context.Context, mode byte) (uint32, error) {
	out, err := r.fileCall(ctx, "Open", id.PublishSubscribePubSubConfigurationOpen, 1, ua.MustVariant(mode))
	if err != nil {
		return 0, err
	}
	h, ok := out[0].Value().(uint32)
	if !ok {
		return 0, fmt.Errorf("remote: Open returned %T, want a UInt32", out[0].Value())
	}
	return h, nil
}

func (r *Client) closeFile(ctx context.Context, h uint32) error {
	_, err := r.fileCall(ctx, "Close", id.PublishSubscribePubSubConfigurationClose, 0, ua.MustVariant(h))
	return err
}

// ReadConfiguration reads the PubSubConfiguration file: the configuration of
// the server.
func (r *Client) ReadConfiguration(ctx context.Context) (*ua.PubSubConfiguration2DataType, error) {
	h, err := r.openFile(ctx, openRead)
	if err != nil {
		return nil, err
	}
	var b []byte
	for {
		out, err := r.fileCall(ctx, "Read", id.PublishSubscribePubSubConfigurationRead, 1, ua.MustVariant(h), ua.MustVariant(int32(configChunk)))
		if err != nil {
			return nil, errors.Join(err, r.closeFile(ctx, h))
		}
		chunk, _ := out[0].Value().([]byte)
		if len(chunk) == 0 {
			break
		}
		b = append(b, chunk...)
	}
	if err := r.closeFile(ctx, h); err != nil {
		return nil, err
	}
	var fd ua.UABinaryFileDataType
	if _, err := ua.Decode(b, &fd); err != nil {
		return nil, fmt.Errorf("remote: decoding the PubSubConfiguration file: %w", err)
	}
	if fd.Body != nil {
		if eo, ok := fd.Body.Value().(*ua.ExtensionObject); ok && eo != nil {
			if cfg, ok := eo.Value.(*ua.PubSubConfiguration2DataType); ok && cfg != nil {
				return cfg, nil
			}
		}
	}
	return nil, fmt.Errorf("remote: the PubSubConfiguration file has no PubSubConfiguration2DataType: %w", ua.StatusBadTypeMismatch)
}

// ReservedIDs is the result of ReserveIDs.
type ReservedIDs struct {
	DefaultPublisherID *ua.Variant
	WriterGroupIDs     []uint16
	DataSetWriterIDs   []uint16
}

// ReserveIDs reserves WriterGroupIds and DataSetWriterIds for the session
// (Part 14 §9.1.3.7.5) and returns the default PublisherId of the server for
// a transport profile.
func (r *Client) ReserveIDs(ctx context.Context, transportProfileURI string, writerGroups, dataSetWriters uint16) (*ReservedIDs, error) {
	out, err := r.fileCall(ctx, "ReserveIds", id.PublishSubscribePubSubConfigurationReserveIDs, 3,
		ua.MustVariant(transportProfileURI), ua.MustVariant(writerGroups), ua.MustVariant(dataSetWriters))
	if err != nil {
		return nil, err
	}
	res := &ReservedIDs{DefaultPublisherID: out[0]}
	res.WriterGroupIDs, _ = out[1].Value().([]uint16)
	res.DataSetWriterIDs, _ = out[2].Value().([]uint16)
	return res, nil
}

// UpdateResult is the result of UpdateConfiguration.
type UpdateResult struct {
	// ChangesApplied is whether the server applied one or more changes.
	ChangesApplied bool
	// Results has a status per reference.
	Results []ua.StatusCode
	// Values are the names and identifiers of the added and matched
	// elements.
	Values []*ua.PubSubConfigurationValueDataType
	// Objects are the NodeIds of the objects of the references, if the
	// server returns them.
	Objects []*ua.NodeID
}

// UpdateConfiguration writes cfg to the PubSubConfiguration file and applies
// the element operations of refs with CloseAndUpdate (Part 14
// §9.1.3.7.6). With requireComplete the server applies the changes only if
// it can apply all of them.
func (r *Client) UpdateConfiguration(ctx context.Context, cfg *ua.PubSubConfiguration2DataType, refs []*ua.PubSubConfigurationRefDataType, requireComplete bool) (*UpdateResult, error) {
	ns, err := r.c.NamespaceArray(ctx)
	if err != nil {
		return nil, err
	}
	b, err := ua.Encode(&ua.UABinaryFileDataType{Namespaces: ns, Body: ua.MustVariant(ua.NewExtensionObject(cfg))})
	if err != nil {
		return nil, err
	}
	h, err := r.openFile(ctx, openWriteErase)
	if err != nil {
		return nil, err
	}
	for len(b) > 0 {
		n := min(len(b), configChunk)
		if _, err := r.fileCall(ctx, "Write", id.PublishSubscribePubSubConfigurationWrite, 0, ua.MustVariant(h), ua.MustVariant(b[:n])); err != nil {
			return nil, errors.Join(err, r.closeFile(ctx, h))
		}
		b = b[n:]
	}
	out, err := r.fileCall(ctx, "CloseAndUpdate", id.PublishSubscribePubSubConfigurationCloseAndUpdate, 3,
		ua.MustVariant(h), ua.MustVariant(requireComplete), structsArg(refs))
	if err != nil {
		var e *Error
		if errors.As(err, &e) && e.Status != ua.StatusBadInvalidArgument {
			// The handle is still open after a call the server refused.
			err = errors.Join(err, r.closeFile(ctx, h))
		}
		return nil, err
	}
	res := &UpdateResult{}
	res.ChangesApplied, _ = out[0].Value().(bool)
	res.Results, _ = out[1].Value().([]ua.StatusCode)
	if eos, ok := out[2].Value().([]*ua.ExtensionObject); ok {
		for _, eo := range eos {
			if v, ok := eo.Value.(*ua.PubSubConfigurationValueDataType); ok {
				res.Values = append(res.Values, v)
			}
		}
	}
	if len(out) > 3 {
		res.Objects, _ = out[3].Value().([]*ua.NodeID)
	}
	return res, nil
}

// Ref returns the reference of an element operation of UpdateConfiguration:
// op is ua.PubSubConfigurationRefMaskElementAdd, Match, Modify or Remove
// (Add and Match may be combined), kind one of the Reference bits, and the
// indices locate the element in the configuration written.
func Ref(op, kind ua.PubSubConfigurationRefMask, connection, group, element uint16) *ua.PubSubConfigurationRefDataType {
	return &ua.PubSubConfigurationRefDataType{ConfigurationMask: op | kind, ConnectionIndex: connection, GroupIndex: group, ElementIndex: element}
}
