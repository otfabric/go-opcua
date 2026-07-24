// SPDX-License-Identifier: MIT

package opcua

// SubscriptionRecoveryOutcome describes what happened to a subscription during
// automatic reconnect recovery.
type SubscriptionRecoveryOutcome string

const (
	// SubscriptionRecoveryTransferred means the subscription was successfully
	// transferred to the new session and all expected messages were republished.
	SubscriptionRecoveryTransferred SubscriptionRecoveryOutcome = "transferred"

	// SubscriptionRecoveryRepublished means some or all buffered notifications
	// were recovered via Republish after a successful TransferSubscriptions.
	SubscriptionRecoveryRepublished SubscriptionRecoveryOutcome = "republished"

	// SubscriptionRecoveryRecreated means the subscription could not be
	// transferred and was recreated as a new subscription on the server.
	SubscriptionRecoveryRecreated SubscriptionRecoveryOutcome = "recreated"

	// SubscriptionRecoveryPartial means recovery was only partially successful:
	// some sequence numbers were republished but a gap remains.
	SubscriptionRecoveryPartial SubscriptionRecoveryOutcome = "partially_recovered"

	// SubscriptionRecoveryUnrecoverableGap means the client's expected next
	// sequence number is not present in the server's retransmission buffer;
	// notifications between the last delivered message and the oldest buffered
	// message are permanently lost.
	SubscriptionRecoveryUnrecoverableGap SubscriptionRecoveryOutcome = "unrecoverable_gap"
)

// SubscriptionRecoveryEvent is delivered to the handler registered via
// [WithSubscriptionRecoveryHandler] after each subscription recovery attempt
// during automatic reconnect.
type SubscriptionRecoveryEvent struct {
	// SubscriptionID is the OPC UA subscription identifier on the server.
	SubscriptionID uint32

	// Outcome describes the recovery result for this subscription.
	Outcome SubscriptionRecoveryOutcome

	// AvailableSequenceNumbers contains the sequence numbers that the server
	// reported as available for retransmission at the time of recovery.
	// It is empty when the subscription was recreated or transfer failed.
	AvailableSequenceNumbers []uint32

	// Detail is a human-readable description of the outcome, suitable for
	// logging or display. It is never empty.
	Detail string
}
