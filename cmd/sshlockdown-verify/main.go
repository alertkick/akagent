// Command sshlockdown-verify loads (without attaching) both SSH-lockdown
// BPF programs so the kernel verifier vets them, then reports which
// blocker SelectBlocker would pick on this host. Run as root on a dev
// box after regenerating bindings; it makes no persistent changes.
package main

import (
	"fmt"
	"os"

	"akagent/ebpf/bpfgen"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintf(os.Stderr, "memlock: %v\n", err)
	}

	failed := false

	var lsmObjs bpfgen.SshlockdownObjects
	if err := bpfgen.LoadSshlockdownObjects(&lsmObjs, nil); err != nil {
		failed = true
		fmt.Printf("LSM  load: FAIL: %v\n", verifierDetail(err))
	} else {
		fmt.Println("LSM  load: OK (verifier accepted)")
		lsmObjs.Close()
	}

	var tcObjs bpfgen.SshlockdowntcObjects
	if err := bpfgen.LoadSshlockdowntcObjects(&tcObjs, nil); err != nil {
		failed = true
		fmt.Printf("TC   load: FAIL: %v\n", verifierDetail(err))
	} else {
		fmt.Println("TC   load: OK (verifier accepted)")
		tcObjs.Close()
	}

	if failed {
		os.Exit(1)
	}
}

func verifierDetail(err error) string {
	var ve *ebpf.VerifierError
	if ok := asVerifierError(err, &ve); ok {
		return fmt.Sprintf("%+v", ve)
	}
	return err.Error()
}

func asVerifierError(err error, target **ebpf.VerifierError) bool {
	for e := err; e != nil; {
		if ve, ok := e.(*ebpf.VerifierError); ok {
			*target = ve
			return true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}
