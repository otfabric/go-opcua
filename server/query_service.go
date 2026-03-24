package server

import (
	"context"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uasc"
)

// QueryService implements the Query Service Set.
//
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.9
type QueryService struct {
	srv *Server
}

// QueryFirst implements the OPC UA QueryFirst service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.9.3
func (s *QueryService) QueryFirst(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.srv.cfg.logger.Debugf("handling request type=%T", r)

	req, err := safeReq[*ua.QueryFirstRequest](r)
	if err != nil {
		return nil, err
	}
	return serviceUnsupported(req.RequestHeader), nil
}

// QueryNext implements the OPC UA QueryNext service.
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.9.4
func (s *QueryService) QueryNext(ctx context.Context, sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	s.srv.cfg.logger.Debugf("handling request type=%T", r)

	req, err := safeReq[*ua.QueryNextRequest](r)
	if err != nil {
		return nil, err
	}
	return serviceUnsupported(req.RequestHeader), nil
}
