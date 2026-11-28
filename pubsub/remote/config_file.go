// SPDX-License-Identifier: MIT

package remote

import (
	"context"
	"errors"
	"fmt"

	"github.com/otfabric/go-opcua/filetransfer"
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uamethod"
)

// PubSubConfiguration is the PubSubConfiguration file object of the
// PublishSubscribe object (Part 14 §9.1.3.7).
var PubSubConfiguration = ua.NewNumericNodeID(0, id.PublishSubscribePubSubConfiguration)

// configChunk is the size of the Read and Write calls on the file.
const configChunk = 64 << 10

func (r *Client) fileCall(ctx context.Context, name string, method uint32, outputs int, args ...*ua.Variant) ([]*ua.Variant, error) {
	return r.call(ctx, PubSubConfiguration, name, method, outputs, args...)
}

// configFileMethods are the FileType Methods of PubSubConfiguration.
var configFileMethods = map[string]uint32{
	"Open":        id.PublishSubscribePubSubConfigurationOpen,
	"Close":       id.PublishSubscribePubSubConfigurationClose,
	"Read":        id.PublishSubscribePubSubConfigurationRead,
	"Write":       id.PublishSubscribePubSubConfigurationWrite,
	"GetPosition": id.PublishSubscribePubSubConfigurationGetPosition,
	"SetPosition": id.PublishSubscribePubSubConfigurationSetPosition,
}

// configFile returns PubSubConfiguration as a FileType Object (OPC 10000-20
// §4.2) whose Methods are called like the other Methods of r, so a failing
// call is an *Error.
func (r *Client) configFile() *filetransfer.Object {
	o := filetransfer.ObjectFunc(func(ctx context.Context, m *uamethod.Method, in []*ua.Variant) ([]*ua.Variant, error) {
		return r.fileCall(ctx, m.Name, configFileMethods[m.Name], 0, in...)
	})
	o.Chunk = configChunk
	return o
}

// ReadConfiguration reads the PubSubConfiguration file: the configuration of
// the server.
func (r *Client) ReadConfiguration(ctx context.Context) (*ua.PubSubConfiguration2DataType, error) {
	b, err := r.configFile().ReadAll(ctx, 0)
	if err != nil {
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
	in := uamethod.PubSubConfigurationTypeReserveIDsInput{
		TransportProfileURI:    transportProfileURI,
		NumReqWriterGroupIDs:   writerGroups,
		NumReqDataSetWriterIDs: dataSetWriters,
	}
	out, err := r.fileCall(ctx, "ReserveIds", id.PublishSubscribePubSubConfigurationReserveIDs, 0, in.Pack()...)
	if err != nil {
		return nil, err
	}
	var o uamethod.PubSubConfigurationTypeReserveIDsOutput
	if err := o.Unpack(out); err != nil {
		return nil, fmt.Errorf("remote: %w", err)
	}
	return &ReservedIDs{DefaultPublisherID: o.DefaultPublisherID, WriterGroupIDs: o.WriterGroupIDs, DataSetWriterIDs: o.DataSetWriterIDs}, nil
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
	f, err := r.configFile().Open(ctx, ua.OpenFileModeWrite|ua.OpenFileModeEraseExisting)
	if err != nil {
		return nil, err
	}
	if err := f.Write(ctx, b); err != nil {
		return nil, errors.Join(err, f.Close(ctx))
	}
	in := uamethod.PubSubConfigurationTypeCloseAndUpdateInput{
		FileHandle:            f.Handle(),
		RequireCompleteUpdate: requireComplete,
		// No references are an empty array, not the null array.
		ConfigurationReferences: append([]*ua.PubSubConfigurationRefDataType{}, refs...),
	}
	out, err := r.fileCall(ctx, "CloseAndUpdate", id.PublishSubscribePubSubConfigurationCloseAndUpdate, 3, in.Pack()...)
	if err != nil {
		var e *Error
		if errors.As(err, &e) && e.Status != ua.StatusBadInvalidArgument {
			// The handle is still open after a call the server refused.
			err = errors.Join(err, f.Close(ctx))
		}
		return nil, err
	}
	if len(out) == 3 {
		// A server may leave out ConfigurationObjects, the last output.
		out = append(out, ua.MustVariant([]*ua.NodeID(nil)))
	}
	var o uamethod.PubSubConfigurationTypeCloseAndUpdateOutput
	if err := o.Unpack(out); err != nil {
		return nil, fmt.Errorf("remote: %w", err)
	}
	res := &UpdateResult{ChangesApplied: o.ChangesApplied, Results: o.ReferencesResults, Objects: o.ConfigurationObjects}
	for _, v := range o.ConfigurationValues {
		if v != nil {
			res.Values = append(res.Values, v)
		}
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
