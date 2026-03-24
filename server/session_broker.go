package server

import (
	mrand "math/rand"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/otfabric/go-opcua/logger"
	"github.com/otfabric/go-opcua/ua"
)

type session struct {
	cfg sessionConfig

	ID                *ua.NodeID
	AuthTokenID       *ua.NodeID
	serverNonce       []byte
	remoteCertificate []byte

	// identityToken is the user identity provided during ActivateSession.
	identityToken ua.IdentityToken

	// roles is the set of well-known role NodeIDs assigned to this session
	// based on the identity token. Set during ActivateSession.
	roles []*ua.NodeID

	PublishRequests chan PubReq
}

type sessionConfig struct {
	sessionTimeout time.Duration
}

type sessionBroker struct {
	// mu protects concurrent modification of s
	mu sync.Mutex

	// s contains all sessions watched by the session broker
	s      map[string]*session
	logger logger.Logger
}

func newSessionBroker(logger logger.Logger) *sessionBroker {
	return &sessionBroker{
		s:      make(map[string]*session),
		logger: logger,
	}
}

func (sb *sessionBroker) NewSession() *session {
	s := &session{
		ID:              ua.NewGUIDNodeID(1, uuid.New().String()),
		AuthTokenID:     ua.NewNumericNodeID(0, uint32(mrand.Int31())),
		PublishRequests: make(chan PubReq, 100),
	}

	sb.mu.Lock()
	sb.s[s.AuthTokenID.String()] = s
	sb.mu.Unlock()

	return s
}

func (sb *sessionBroker) Close(authToken *ua.NodeID) error {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if sb.s[authToken.String()] == nil {
		sb.logger.Warnf("sessionBroker.Close: error looking up session auth_token=%v", authToken)
	}
	delete(sb.s, authToken.String())

	return nil
}

func (sb *sessionBroker) Session(authToken *ua.NodeID) *session {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	s := sb.s[authToken.String()]
	if s == nil {
		sb.logger.Warnf("sessionBroker.Session: error looking up session auth_token=%v", authToken)
	}

	return s
}
