// SPDX-License-Identifier: MIT

package fxcm_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxcm"
	"github.com/otfabric/go-opcua/uafx/fxserver"
	"github.com/otfabric/go-opcua/uafx/fxstore"
)

// The crash tests of the ConnectionManager (design §7.2, §9.1): the test
// binary runs itself as a child that serves two AutomationComponents and
// runs a Manager on a FileStore, stops at a named point of the journal and
// says so on its stdout; the parent kills it (SIGKILL on Unix) and opens a
// Manager on the same directory, without the AutomationComponents (they
// died with the child, and a restarted Manager needs none, §6.4).
const (
	cmCrashEnv    = "FXCM_CRASH_POINT"
	cmCrashDirEnv = "FXCM_CRASH_DIR"
)

// cmFX is what a crash scenario acts on in the child.
type cmFX struct {
	m    *fxcm.Manager
	a, b *ac
	key  fxcm.SetKey
}

type cmCrashScenario struct {
	point        string
	prepare, act func(t *testing.T, f *cmFX)
	check        func(t *testing.T, m *fxcm.Manager)
}

func addSet(t *testing.T, f *cmFX) {
	cfg, err := f.m.Add(e2eConf(t, "Crash", f.a, f.b))
	require.NoError(t, err)
	f.key = cfg.Key()
}

func establishSet(t *testing.T, f *cmFX) {
	addSet(t, f)
	res := process(t, f.m, uafx.ActionEstablishConnectionsEnabled, f.key)
	require.Equal(t, fxcm.StateReady, res.State, "%+v", res.Failures)
}

func processSet(t *testing.T, f *cmFX) {
	st := f.m.Process(uafx.ActionEstablishConnectionsEnabled, f.key)
	require.Len(t, st, 1)
	require.NoError(t, st[0].Err)
	_, _ = st[0].Run.Wait(context.Background()) // the child is killed in the run
}

// abortingSet adds a set whose second endpoint fails at its
// AutomationComponent (a ConfigurationData of the wrong type), so that the
// run with RollbackOnError TRUE rolls back the first.
func abortingSet(t *testing.T, f *cmFX) {
	conf := e2eConf(t, "Crash", f.a, f.b)
	conf.Connections[0].Endpoint2.ConfigurationData[0].Value = ua.MustVariant("not a Double")
	cfg, err := f.m.Add(conf)
	require.NoError(t, err)
	f.key = cfg.Key()
}

func crashKey() fxcm.SetKey { return fxcm.SetKey{Name: "Crash"} }

func owedKinds(t *testing.T, m *fxcm.Manager) map[fxcm.OwedKind]bool {
	t.Helper()
	st, ok := m.Status(crashKey())
	require.True(t, ok)
	require.NotNil(t, st.Recovery)
	out := map[fxcm.OwedKind]bool{}
	for _, w := range st.Recovery.Owed {
		out[w.Kind] = true
	}
	return out
}

func noSet(t *testing.T, m *fxcm.Manager) {
	_, ok := m.Status(crashKey())
	require.False(t, ok, "the change was not durable: the old configuration")
}

func readyNothingOwed(t *testing.T, m *fxcm.Manager) {
	st, ok := m.Status(crashKey())
	require.True(t, ok, "the change was durable: the new configuration")
	assert.Equal(t, fxcm.StateReady, st.State)
	assert.Empty(t, st.Recovery.Owed)
	assert.Empty(t, st.Endpoints)
}

func owes(kinds ...fxcm.OwedKind) func(t *testing.T, m *fxcm.Manager) {
	return func(t *testing.T, m *fxcm.Manager) {
		st, _ := m.Status(crashKey())
		assert.Equal(t, fxcm.StateError, st.State, "the journal shows owed work")
		got := owedKinds(t, m)
		for _, k := range kinds {
			assert.True(t, got[k], "%v owed: %+v", k, st.Recovery.Owed)
		}
		for _, e := range st.Endpoints {
			assert.Equal(t, fxcm.Unverified, e.Class, "no loaded record is trusted")
		}
		assert.Zero(t, m.Counters().EstablishCallCount+m.Counters().CloseCallCount, "owed work is exposed, not executed")
	}
}

var cmCrashScenarios = map[string]cmCrashScenario{
	"add before the set write": {point: "set.before-apply", act: addSet, check: noSet},
	"add after the set write":  {point: "set.after-apply", act: addSet, check: readyNothingOwed},
	"establish before the first intent": {point: "call.before-intent", prepare: addSet, act: processSet,
		check: readyNothingOwed},
	"establish with an intent written": {point: "call.after-intent", prepare: addSet, act: processSet,
		check: owes(fxcm.OwedCall, fxcm.OwedRollback)},
	"establish with a call sent": {point: "call.after-send", prepare: addSet, act: processSet,
		check: owes(fxcm.OwedCall, fxcm.OwedRollback)},
	"rollback before its first close": {point: "rollback.started", prepare: abortingSet, act: processSet,
		check: owes(fxcm.OwedRollback)},
	"replace during the closes": {point: "set.before-apply", prepare: establishSet,
		act: func(t *testing.T, f *cmFX) {
			_, _ = f.m.Replace(context.Background(), e2eConf(t, "Crash", f.a, f.b))
		},
		check: func(t *testing.T, m *fxcm.Manager) {
			owes(fxcm.OwedSetChange)(t, m)
			st, _ := m.Status(crashKey())
			assert.Empty(t, st.Endpoints, "the closes completed with their records")
		}},
}

// TestCrash kills a Manager at each point of its journal and checks what a
// Manager on the same store has: the configuration as committed, the owed
// work, and no trusted ownership record (the gate of C3.2).
func TestCrash(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("starts child processes")
	}
	for name, sc := range cmCrashScenarios {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir() + "/store"
			runCMCrashChild(t, name, dir, sc.point)
			store, err := fxstore.OpenFile(dir, fxstore.Limits{})
			require.NoError(t, err)
			t.Cleanup(func() { _ = store.Close() })
			m := newManager(t, fxcm.Options{Store: store})
			ss, _ := m.StoreStatus()
			require.Empty(t, ss.Failed)
			sc.check(t, m)
		})
	}
}

func runCMCrashChild(t *testing.T, name, dir, point string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashChild$", "-test.count=1", "-test.timeout=2m")
	cmd.Env = append(os.Environ(), cmCrashEnv+"="+name, cmCrashDirEnv+"="+dir)
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
		if line == "FXCMCRASH "+point {
			reached = true
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
	name := os.Getenv(cmCrashEnv)
	if name == "" {
		t.Skip("the child of TestCrash")
	}
	sc := cmCrashScenarios[name]
	store, err := fxstore.OpenFile(os.Getenv(cmCrashDirEnv), fxstore.Limits{})
	require.NoError(t, err)
	f := &cmFX{a: newAC(t, "a", fxserver.ConnectionOptions{}), b: newAC(t, "b", fxserver.ConnectionOptions{})}
	f.m = newManager(t, fxcm.Options{Store: store})
	if sc.prepare != nil {
		sc.prepare(t, f)
	}
	fxcm.SetCrashPoint(f.m, func(p string) {
		if p != sc.point {
			return
		}
		fmt.Println("FXCMCRASH " + p)
		_ = os.Stdout.Sync()
		select {} // until the parent kills the process
	})
	sc.act(t, f)
	fmt.Println("FXCMDONE: the crash point was not reached")
	select {}
}
