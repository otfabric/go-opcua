// SPDX-License-Identifier: MIT

package fxserver_test

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxserver"
	"github.com/otfabric/go-opcua/uafx/fxstore"
)

// The crash tests (design §9.1): the test binary runs itself as a child
// that serves a persistent AutomationComponent on a FileStore, stops at a
// named point of a persistence protocol and says so on its stdout; the
// parent kills it (SIGKILL on Unix) and starts a server on the same
// directory.
const (
	crashEnv    = "FXSERVER_CRASH_POINT"
	crashDirEnv = "FXSERVER_CRASH_DIR"
)

// crashScenario is what the child does before it stops at point, and what
// the restarted server must show.
type crashScenario struct {
	point string
	// prepare runs before the crash point is armed; act runs with it.
	prepare, act func(t *testing.T, f *fx)
	check        func(t *testing.T, f *fx)
}

func establishP(t *testing.T, f *fx) { f.persistent(t, "P") }

func closeP(remove bool) func(t *testing.T, f *fx) {
	return func(t *testing.T, f *fx) {
		_, _ = f.close(t, remove, f.endpointNamed("P")) // the child is killed inside the call
	}
}

func restoredP(want uafx.ConnectionEndpointStatus) func(t *testing.T, f *fx) {
	return func(t *testing.T, f *fx) {
		ep := f.endpointNamed("P")
		require.NotNil(t, ep, "P is restored")
		f.waitStatus(t, ep, want)
		require.Equal(t, 1, f.conns.Persistence().Records)
		if want == uafx.ConnectionEndpointReady {
			time.Sleep(50 * time.Millisecond)
			st, _ := f.conns.Status(ep)
			require.Equal(t, want, st, "restored disabled")
		}
	}
}

func goneP(t *testing.T, f *fx) {
	require.Nil(t, f.endpointNamed("P"), "no phantom endpoint, nothing removed comes back")
	require.Equal(t, 0, f.conns.Persistence().Records)
	require.Empty(t, f.srv.PubSub().Configuration().Connections)
}

var crashScenarios = map[string]crashScenario{
	"establish before the commit": {point: "establish.before-commit", act: establishP, check: goneP},
	"establish after the commit":  {point: "establish.after-commit", act: establishP, check: restoredP(uafx.ConnectionEndpointOperational)},
	"disable before the intent":   {point: "disable.before-intent", prepare: establishP, act: closeP(false), check: restoredP(uafx.ConnectionEndpointOperational)},
	"disable after the intent":    {point: "disable.after-intent", prepare: establishP, act: closeP(false), check: restoredP(uafx.ConnectionEndpointReady)},
	"remove before the intent":    {point: "close.before-intent", prepare: establishP, act: closeP(true), check: restoredP(uafx.ConnectionEndpointOperational)},
	"remove after the intent":     {point: "close.after-intent", prepare: establishP, act: closeP(true), check: goneP},
	"remove after the runtime":    {point: "close.after-runtime", prepare: establishP, act: closeP(true), check: goneP},
}

// TestCrash kills a server at each point of the persistence protocols and
// checks what a restart on the same store restores: persistent endpoints
// survive an abrupt restart with the right communication state, and no
// durable removal or disable is undone (the gate of C3.1).
func TestCrash(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("starts child processes")
	}
	for name, sc := range crashScenarios {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir() + "/store"
			runCrashChild(t, name, dir, sc.point)
			store, err := fxstore.OpenFile(dir, fxstore.Limits{})
			require.NoError(t, err)
			t.Cleanup(func() { _ = store.Close() })
			require.Equal(t, fxstore.DurabilityPowerLoss, store.Durability())
			f := newFX(t, fxserver.ConnectionOptions{Store: store})
			require.Empty(t, f.conns.Quarantined())
			sc.check(t, f)
		})
	}
}

// runCrashChild runs the scenario name in a child until it reaches point,
// and kills it.
func runCrashChild(t *testing.T, name, dir, point string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashChild$", "-test.count=1", "-test.timeout=2m")
	cmd.Env = append(os.Environ(), crashEnv+"="+name, crashDirEnv+"="+dir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	timer := time.AfterFunc(time.Minute, func() { _ = cmd.Process.Kill() })
	defer timer.Stop()
	reached := false
	var lines []string
	sc := bufio.NewScanner(out)
	for sc.Scan() {
		line := sc.Text()
		lines = append(lines, line)
		if line == "FXCRASH "+point {
			reached = true
			break
		}
		if strings.HasPrefix(line, "FXDONE") {
			// The child missed its point: no need to wait for the timer.
			break
		}
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	require.True(t, reached, "the child did not reach %s:\n%s\n%s", point, strings.Join(lines, "\n"), stderr.String())
}

// TestCrashChild is the child of TestCrash; it does nothing in a normal
// run.
func TestCrashChild(t *testing.T) {
	name := os.Getenv(crashEnv)
	if name == "" {
		t.Skip("the child of TestCrash")
	}
	sc := crashScenarios[name]
	store, err := fxstore.OpenFile(os.Getenv(crashDirEnv), fxstore.Limits{})
	require.NoError(t, err)
	f := newFX(t, fxserver.ConnectionOptions{Store: store})
	if sc.prepare != nil {
		sc.prepare(t, f)
	}
	fxserver.SetCrashPoint(f.conns, func(p string) {
		if p != sc.point {
			return
		}
		fmt.Println("FXCRASH " + p)
		_ = os.Stdout.Sync()
		select {} // until the parent kills the process
	})
	sc.act(t, f)
	fmt.Println("FXDONE: the crash point was not reached")
	_ = os.Stdout.Sync()
	t.Fatalf("the crash point %s was not reached", sc.point)
}
