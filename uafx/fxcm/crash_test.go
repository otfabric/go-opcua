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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx"
	"github.com/otfabric/go-opcua/uafx/fxcm"
	"github.com/otfabric/go-opcua/uafx/fxserver"
	"github.com/otfabric/go-opcua/uafx/fxstore"
	"github.com/otfabric/go-opcua/uafx/fxstore/storetest"
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
	fail *failing // the store of m, when the scenario wraps it
}

type cmCrashScenario struct {
	point string
	// nth is the occurrence of point to stop at, 0 the first.
	nth          int
	prepare, act func(t *testing.T, f *cmFX)
	check        func(t *testing.T, m *fxcm.Manager)
	// restart: after prepare the child closes its Manager and opens
	// another on the same store (Verify Manual), whose run act starts.
	restart bool
	// wrap: the store of the child is a failing store (cmFX.fail).
	wrap bool
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

// unverifiedNothingSent: the records of the established set are loaded,
// Unverified, and the restarted Manager sent nothing.
func unverifiedNothingSent(t *testing.T, m *fxcm.Manager) {
	st, ok := m.Status(crashKey())
	require.True(t, ok)
	require.Len(t, st.Endpoints, 2, "no record is lost")
	for _, e := range st.Endpoints {
		assert.Equal(t, fxcm.Unverified, e.Class, "no loaded record is trusted")
	}
	assert.Zero(t, m.Counters().EstablishCallCount+m.Counters().CloseCallCount)
}

func reconcileSet(t *testing.T, f *cmFX) {
	started := f.m.Reconcile(f.key)
	require.NoError(t, started.Err)
	_, _ = started.Run.Wait(context.Background())
}

var cmCrashScenarios = map[string]cmCrashScenario{
	// C3.3 (design §7.2): the verification of a restarted Manager, before
	// and after the write of its verdicts; nothing it decided is trusted
	// after another restart, and nothing is lost.
	"verification before its write": {point: "verify.before-write", prepare: establishSet, restart: true, act: processSet,
		check: unverifiedNothingSent},
	"verification after its write": {point: "verify.after-write", prepare: establishSet, restart: true, act: processSet,
		check: unverifiedNothingSent},
	// An adoption before the enablement of what it kept has sent nothing:
	// the endpoints are as they were, the records kept, nothing is owed;
	// the next establish adopts them again.
	"adoption before the enablement": {point: "adopt.before-enablement", prepare: establishSet, restart: true, act: processSet,
		check: func(t *testing.T, m *fxcm.Manager) {
			unverifiedNothingSent(t, m)
			st, _ := m.Status(crashKey())
			assert.Empty(t, st.Recovery.Owed)
		}},
	// The owed rollback of an earlier run, done by the first step of the
	// next one, before its closes: still owed.
	"owed rollback before its closes": {point: "recover.rollback", wrap: true,
		prepare: func(t *testing.T, f *cmFX) {
			abortingSet(t, f)
			f.fail.arm(storetest.FailNotCommitted, func(b fxstore.Batch) bool {
				for key, v := range b.Puts {
					if strings.HasPrefix(key, "cm/run/") {
						r, err := fxcm.DecodeStored[fxcm.StoredRun](v)
						if err == nil && r.Phase == fxcm.PhaseRollbackRequired {
							return true
						}
					}
				}
				return false
			})
			res := process(t, f.m, uafx.ActionEstablishConnectionsEnabled, f.key)
			require.Equal(t, fxcm.StateError, res.State)
		},
		act:   processSet,
		check: owes(fxcm.OwedRollback)},
	// The owed switch of a set change, completed by a Reconcile, before
	// its write: still owed.
	"owed set change before its switch": {point: "recover.before-switch", wrap: true,
		prepare: func(t *testing.T, f *cmFX) {
			establishSet(t, f)
			f.fail.arm(storetest.FailLost, func(b fxstore.Batch) bool { return putsPrefix("set/")(b) })
			_, err := f.m.Replace(context.Background(), e2eConf(t, "Crash", f.a, f.b))
			require.Error(t, err)
			waitUnfenced(t, f.m)
		},
		act: reconcileSet,
		check: func(t *testing.T, m *fxcm.Manager) {
			owes(fxcm.OwedSetChange)(t, m)
			st, _ := m.Status(crashKey())
			assert.Empty(t, st.Endpoints, "the closes completed with their records")
		}},

	"add before the set write": {point: "set.before-apply", act: addSet, check: noSet},
	"add after the set write":  {point: "set.after-apply", act: addSet, check: readyNothingOwed},
	"establish before the first intent": {point: "call.before-intent", prepare: addSet, act: processSet,
		check: readyNothingOwed},
	// The third intent is of the first call that creates endpoints: the
	// first two reserve ids, one on each AutomationComponent.
	"establish with an intent written": {point: "call.after-intent", nth: 2, prepare: addSet, act: processSet,
		check: func(t *testing.T, m *fxcm.Manager) {
			owes(fxcm.OwedCall, fxcm.OwedRollback)(t, m)
			st, _ := m.Status(crashKey())
			assert.NotEmpty(t, st.Endpoints, "the Names of the intent are held, Unverified")
			// The AutomationComponents died with the child: the run
			// starts, its first step cannot verify, and the Names stay
			// held; nothing is sent (design §6.4).
			res := process(t, m, uafx.ActionEstablishConnectionsEnabled, crashKey())
			assert.Equal(t, fxcm.StateError, res.State)
			assert.Empty(t, res.Created)
			assert.Zero(t, m.Counters().EstablishCallCount+m.Counters().CloseCallCount)
			st, _ = m.Status(crashKey())
			for _, e := range st.Endpoints {
				assert.Equal(t, fxcm.Unverified, e.Class)
			}
			assert.NotEmpty(t, st.Recovery.Unreachable, "the verification attempt is reported")
		}},
	"establish with a call sent": {point: "call.after-send", prepare: addSet, act: processSet,
		check: owes(fxcm.OwedCall, fxcm.OwedRollback)},
	"rollback before its first close": {point: "rollback.started", prepare: abortingSet, act: processSet,
		check: owes(fxcm.OwedRollback)},
	"update between its closes and the switch": {point: "set.before-apply", prepare: establishSet,
		act: func(t *testing.T, f *cmFX) {
			_, _ = f.m.Update(context.Background(), []fxcm.Operation{
				{Op: uafx.ElementReplace, Conf: e2eConf(t, "Crash", f.a, f.b)},
				{Op: uafx.ElementAdd, Conf: e2eConf(t, "CrashNew", f.a, f.b)},
			}, true)
		},
		check: func(t *testing.T, m *fxcm.Manager) {
			owes(fxcm.OwedSetChange)(t, m)
			st, _ := m.Status(crashKey())
			for _, w := range st.Recovery.Owed {
				if w.Kind == fxcm.OwedSetChange {
					assert.Len(t, w.Changes, 2, "the parent transaction of the Update")
				}
			}
			_, ok := m.Status(fxcm.SetKey{Name: "CrashNew"})
			assert.False(t, ok)
			// Stand-ins: the child's AutomationComponents died with it.
			_, err := m.Add(e2eConf(t, "CrashNew", &ac{uri: "urn:go-opcua:fxcm:gone1", url: "opc.tcp://localhost:1"},
				&ac{uri: "urn:go-opcua:fxcm:gone2", url: "opc.tcp://localhost:2"}))
			assert.Equal(t, ua.StatusBadInvalidState, fxcm.StatusOf(err), "the key the owed change adds is held: %v", err)
		}},
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

// cmCrashDone starts the line a child of TestCrash prints when its action
// ended without reaching its crash point.
const cmCrashDone = "FXCMDONE"

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
		if strings.HasPrefix(line, cmCrashDone) {
			// The child missed its point: fail now, not at the timer.
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
	file, err := fxstore.OpenFile(os.Getenv(cmCrashDirEnv), fxstore.Limits{})
	require.NoError(t, err)
	var store fxstore.Store = file
	f := &cmFX{a: newAC(t, "a", fxserver.ConnectionOptions{}), b: newAC(t, "b", fxserver.ConnectionOptions{})}
	if sc.wrap {
		f.fail = &failing{Store: file}
		store = f.fail
	}
	f.m = newManager(t, fxcm.Options{Store: store})
	if sc.prepare != nil {
		sc.prepare(t, f)
	}
	if sc.restart {
		require.NoError(t, f.m.Close())
		f.m = newManager(t, fxcm.Options{Store: store, Verify: fxcm.VerifyOptions{Manual: true}})
	}
	var mu sync.Mutex
	seen := 0
	crashed := false
	fxcm.SetCrashPoint(f.m, func(p string) {
		mu.Lock()
		if crashed {
			// The process is "dead": calls running in parallel on the
			// other AutomationComponent must not write past the crash
			// while the parent has not killed it yet.
			mu.Unlock()
			select {}
		}
		if p != sc.point {
			mu.Unlock()
			return
		}
		n := seen
		seen++
		if n != sc.nth {
			mu.Unlock()
			return
		}
		crashed = true
		mu.Unlock()
		fmt.Println("FXCMCRASH " + p)
		_ = os.Stdout.Sync()
		select {} // until the parent kills the process
	})
	sc.act(t, f)
	fmt.Println(cmCrashDone + ": the crash point was not reached")
	select {}
}
