// SPDX-License-Identifier: MIT

package ua

import "testing"

func TestNotification_Interface(t *testing.T) {
	// Ensure all three notification types satisfy the Notification interface
	// and that calling the marker method doesn't panic.
	var dcn Notification = &DataChangeNotification{}
	dcn.isNotification()

	var enl Notification = &EventNotificationList{}
	enl.isNotification()

	var scn Notification = &StatusChangeNotification{}
	scn.isNotification()
}
