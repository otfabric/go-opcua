//go:build integration

// Package uatest provides integration test helpers for testing against the Python OPC UA server.
package uatest

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/errors"
	"github.com/otfabric/go-opcua/ua"
)

// Server is the test server interface used by integration tests.
type Server interface {
	URL() string
	Close() error
}

// PythonServer runs a python test server.
type PythonServer struct {
	// Path is the path to the Python server.
	Path string

	// Endpoint is the endpoint address which will be set
	// after the server has started.
	Endpoint string

	// Opts contains the client options required to connect to the server.
	// They are valid after the server has been started.
	Opts []opcua.Option

	cmd    *exec.Cmd
	waitch chan error
}

// NewPythonServer creates a test server and starts it. The function
// panics if the server cannot be started.
func NewPythonServer(path string) *PythonServer {
	s := &PythonServer{Path: path, waitch: make(chan error)}
	if err := s.Run(); err != nil {
		panic(err)
	}
	return s
}

func (s *PythonServer) Run() error {
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	path := filepath.Join(wd, s.Path)

	py, err := exec.LookPath("python3")
	if err != nil {
		// fallback to python and hope it still points to a python3 version.
		// the Windows python3 installer doesn't seem to create a `python3.exe`
		py, err = exec.LookPath("python")
		if err != nil {
			return fmt.Errorf("%w: unable to find Python executable", errors.ErrNotConnected)
		}
	}

	s.cmd = exec.Command(py, path)
	s.cmd.Stdout = os.Stdout
	s.cmd.Stderr = os.Stderr
	s.Endpoint = "opc.tcp://127.0.0.1:4840"
	s.Opts = []opcua.Option{opcua.SecurityMode(ua.MessageSecurityModeNone)}
	if err := s.cmd.Start(); err != nil {
		return err
	}
	go func() { s.waitch <- s.cmd.Wait() }()

	// wait until endpoint is available
	errch := make(chan error)
	go func() {
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			c, err := net.Dial("tcp", "127.0.0.1:4840")
			if err != nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			c.Close()
			errch <- nil
		}
		errch <- fmt.Errorf("timeout waiting for python server")
	}()

	select {
	case err := <-s.waitch:
		return err
	case err := <-errch:
		return err
	}
}

func (s *PythonServer) Close() error {
	if s.cmd == nil {
		return fmt.Errorf("not running")
	}
	go func() { s.cmd.Process.Kill() }()
	return <-s.waitch
}
