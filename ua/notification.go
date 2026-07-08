// SPDX-License-Identifier: MIT

package ua

// Notification is implemented by the three notification types
// that can be received from a subscription publish response.
type Notification interface {
	isNotification()
}

func (*DataChangeNotification) isNotification()   {}
func (*EventNotificationList) isNotification()    {}
func (*StatusChangeNotification) isNotification() {}
