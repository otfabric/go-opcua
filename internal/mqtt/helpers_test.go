// SPDX-License-Identifier: MIT

package mqtt_test

import (
	"bufio"
	"io"
)

func bufioReader(r io.Reader) *bufio.Reader { return bufio.NewReader(r) }
