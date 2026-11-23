// SPDX-License-Identifier: MIT

package uafx

// InspectClient and InspectWith expose the client interface and the
// inspection of Inspect to the tests of package uafx_test, which inject
// faults and paging between them. They live there because their servers
// need fxserver, which imports uafx.
type InspectClient = client

var InspectWith = inspect
