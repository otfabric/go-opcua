// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
)

// Regression tests for the session state machine (Part 4 §5.6).

// Before the fix every service was served regardless of the session: without
// a session, with a session that was created but never activated, and with
// the token of a closed session.
func TestCheckSessionRequiresActivatedSession(t *testing.T) {
	s := newTestServer()
	sess := s.sb.NewSession()

	header := func(token *ua.NodeID) *ua.RequestHeader {
		return &ua.RequestHeader{RequestHandle: 1, AuthenticationToken: token}
	}
	read := func(token *ua.NodeID) ua.Request {
		return &ua.ReadRequest{RequestHeader: header(token)}
	}

	// no session at all
	if got := s.checkSession(read(ua.NewTwoByteNodeID(0))); got != ua.StatusBadSessionIDInvalid {
		t.Errorf("request without a session: got %v, want BadSessionIdInvalid", got)
	}
	if got := s.checkSession(&ua.ReadRequest{}); got != ua.StatusBadSessionIDInvalid {
		t.Errorf("request without a header: got %v, want BadSessionIdInvalid", got)
	}

	// created but not activated
	if got := s.checkSession(read(sess.AuthTokenID)); got != ua.StatusBadSessionNotActivated {
		t.Errorf("request on a session that was not activated: got %v, want BadSessionNotActivated", got)
	}

	// activated
	sess.activated.Store(true)
	for _, req := range []ua.Request{
		read(sess.AuthTokenID),
		&ua.WriteRequest{RequestHeader: header(sess.AuthTokenID)},
		&ua.BrowseRequest{RequestHeader: header(sess.AuthTokenID)},
		&ua.CallRequest{RequestHeader: header(sess.AuthTokenID)},
		&ua.CreateSubscriptionRequest{RequestHeader: header(sess.AuthTokenID)},
		&ua.PublishRequest{RequestHeader: header(sess.AuthTokenID)},
	} {
		if got := s.checkSession(req); got != ua.StatusOK {
			t.Errorf("%T on an activated session: got %v", req, got)
		}
	}

	// closed
	if err := s.sb.Close(sess.AuthTokenID); err != nil {
		t.Fatal(err)
	}
	if got := s.checkSession(read(sess.AuthTokenID)); got != ua.StatusBadSessionIDInvalid {
		t.Errorf("request on a closed session: got %v, want BadSessionIdInvalid", got)
	}

	// discovery and session establishment need no session
	for _, req := range []ua.Request{
		&ua.GetEndpointsRequest{RequestHeader: header(nil)},
		&ua.FindServersRequest{RequestHeader: header(nil)},
		&ua.CreateSessionRequest{RequestHeader: header(nil)},
		&ua.ActivateSessionRequest{RequestHeader: header(nil)},
		&ua.CloseSessionRequest{RequestHeader: header(nil)},
	} {
		if got := s.checkSession(req); got != ua.StatusOK {
			t.Errorf("%T without a session: got %v, want Good", req, got)
		}
	}
}

// Before the fix sessions never timed out.
func TestSessionBrokerReapsExpiredSessions(t *testing.T) {
	s := newTestServer()

	idle := s.sb.NewSession()
	idle.setTimeout(time.Second)
	busy := s.sb.NewSession()
	busy.setTimeout(time.Second)
	unset := s.sb.NewSession() // no timeout negotiated yet: the default applies

	now := time.Now()

	if got := s.sb.reapExpired(now.Add(500 * time.Millisecond)); len(got) != 0 {
		t.Fatalf("%d session(s) reaped before their timeout", len(got))
	}

	// "busy" is used shortly before the others expire: looking a session up,
	// as every request does, restarts its timeout.
	busy.lastActivity.Store(now.Add(900 * time.Millisecond).UnixNano())

	got := s.sb.reapExpired(now.Add(1500 * time.Millisecond))
	if len(got) != 1 || got[0] != idle {
		t.Fatalf("reaped %d session(s), want exactly the idle one", len(got))
	}
	if s.sb.Session(idle.AuthTokenID) != nil {
		t.Error("the expired session can still be looked up")
	}
	if s.sb.Session(busy.AuthTokenID) != busy {
		t.Error("the session in use was reaped")
	}
	if s.sb.Session(unset.AuthTokenID) != unset {
		t.Error("a session without a negotiated timeout was reaped before the default timeout")
	}

	// the lookup above counts as activity
	if got := s.sb.reapExpired(time.Now().Add(500 * time.Millisecond)); len(got) != 0 {
		t.Errorf("%d session(s) reaped although they were just used", len(got))
	}
	if got := s.sb.reapExpired(time.Now().Add(sessionTimeoutDefault + time.Second)); len(got) != 2 {
		t.Errorf("%d session(s) reaped after the default timeout, want 2", len(got))
	}
}

// Before the fix the id of a new subscription was len(Subs)+1, which is the
// id of an existing subscription as soon as one with a lower id was deleted.
func TestNextSubscriptionIDSkipsIDsInUse(t *testing.T) {
	s := newTestServer()
	ss := s.SubscriptionService

	ss.Mu.Lock()
	defer ss.Mu.Unlock()

	seen := map[uint32]bool{}
	for i := 0; i < 5; i++ {
		id := ss.nextSubscriptionID()
		if id == 0 || seen[id] {
			t.Fatalf("id %d is zero or was handed out twice", id)
		}
		seen[id] = true
		ss.Subs[id] = NewSubscription()
	}
	// delete one in the middle, then allocate again
	for id := range seen {
		delete(ss.Subs, id)
		break
	}
	if id := ss.nextSubscriptionID(); ss.Subs[id] != nil {
		t.Fatalf("id %d of a live subscription was handed out again", id)
	}

	// the counter wraps around without returning 0 or an id in use
	ss.lastID = ^uint32(0) - 1
	ss.Subs[^uint32(0)] = NewSubscription()
	ss.Subs[1] = NewSubscription()
	if id := ss.nextSubscriptionID(); id == 0 || id == ^uint32(0) || id == 1 {
		t.Fatalf("after wrap-around got id %d", id)
	}
}

// A subscription whose lifetime expires must tell the client with a
// StatusChangeNotification (Part 4 §5.13.1.1). There is normally no Publish
// request to answer at that moment, so the notification waits on the session
// and is the first thing the next Publish request gets.
func TestExpiredSubscriptionIsAnnouncedOnNextPublish(t *testing.T) {
	s := newTestServer()
	ss := s.SubscriptionService
	sess := s.sb.NewSession()
	sess.activated.Store(true)

	sub := NewSubscription()
	sub.srv = ss
	sub.ID = 42
	sub.SequenceID = 6
	sub.Session = sess

	sub.announceExpiry(sess)

	req := &ua.PublishRequest{
		RequestHeader:                &ua.RequestHeader{RequestHandle: 9, AuthenticationToken: sess.AuthTokenID},
		SubscriptionAcknowledgements: []*ua.SubscriptionAcknowledgement{},
	}
	resp, err := ss.Publish(context.Background(), nil, req, 1)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	pub, ok := resp.(*ua.PublishResponse)
	if !ok {
		t.Fatalf("Publish returned %T, want an immediate PublishResponse", resp)
	}
	if pub.SubscriptionID != 42 || pub.NotificationMessage.SequenceNumber != 7 {
		t.Errorf("response for subscription %d with sequence number %d, want 42 and 7", pub.SubscriptionID, pub.NotificationMessage.SequenceNumber)
	}
	if len(pub.NotificationMessage.NotificationData) != 1 {
		t.Fatalf("%d notifications, want 1", len(pub.NotificationMessage.NotificationData))
	}
	sc, ok := pub.NotificationMessage.NotificationData[0].Value.(*ua.StatusChangeNotification)
	if !ok || sc.Status != ua.StatusBadTimeout {
		t.Fatalf("notification %#v, want StatusChangeNotification(BadTimeout)", pub.NotificationMessage.NotificationData[0].Value)
	}

	// It is announced once. With no subscription left the next Publish gets
	// BadNoSubscription.
	if _, err := ss.Publish(context.Background(), nil, req, 2); err != ua.StatusBadNoSubscription {
		t.Fatalf("second Publish: %v, want BadNoSubscription", err)
	}
}
