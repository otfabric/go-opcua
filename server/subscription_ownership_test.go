// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-opcua/ua"
	"github.com/stretchr/testify/require"
)

// activatedSession returns an activated session of srv and a request header
// carrying its token.
func activatedSession(t *testing.T, srv *Server) (*session, *ua.RequestHeader) {
	t.Helper()
	sess := srv.sb.NewSession()
	sess.activated.Store(true)
	return sess, &ua.RequestHeader{RequestHandle: 7, AuthenticationToken: sess.AuthTokenID}
}

func TestRepublishAndAckOnlyOwnSubscriptions(t *testing.T) {
	srv := newTestServer()
	svc, sub, _ := newTestSubscription(srv)
	other, otherHdr := activatedSession(t, srv)

	sub.storeSentMessage(&ua.NotificationMessage{SequenceNumber: 3, PublishTime: time.Now()})

	resp, err := svc.Republish(context.Background(), nil, &ua.RepublishRequest{
		RequestHeader: otherHdr, SubscriptionID: sub.ID, RetransmitSequenceNumber: 3}, 1)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadSubscriptionIDInvalid, resp.(*ua.RepublishResponse).ResponseHeader.ServiceResult)
	require.Nil(t, resp.(*ua.RepublishResponse).NotificationMessage)

	res := svc.ackPublishAcknowledgements(other, []*ua.SubscriptionAcknowledgement{{SubscriptionID: sub.ID, SequenceNumber: 3}})
	require.Equal(t, []ua.StatusCode{ua.StatusBadSubscriptionIDInvalid}, res)
	require.True(t, sub.retransmittable(3), "another session cannot acknowledge the message")

	res = svc.ackPublishAcknowledgements(nil, []*ua.SubscriptionAcknowledgement{{SubscriptionID: sub.ID, SequenceNumber: 3}})
	require.Equal(t, []ua.StatusCode{ua.StatusBadSubscriptionIDInvalid}, res)

	res = svc.ackPublishAcknowledgements(sub.Session, []*ua.SubscriptionAcknowledgement{{SubscriptionID: sub.ID, SequenceNumber: 3}})
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, res)
}
