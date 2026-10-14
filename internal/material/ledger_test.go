package material

import (
	"os"
	"os/exec"
	"testing"
)

func TestPersistentLedger(t *testing.T) {
	if os.Getenv("PMEQ_LEDGER_CHILD") == "1" {
		if ClaimPersistent(os.Getenv("PMEQ_LEDGER_DIR"), [16]byte{1}) == nil {
			os.Exit(2)
		}
		return
	}
	d := t.TempDir()
	if e := ClaimPersistent(d, [16]byte{1}); e != nil {
		t.Fatal(e)
	}
	c := exec.Command(os.Args[0], "-test.run=^TestPersistentLedger$")
	c.Env = append(os.Environ(), "PMEQ_LEDGER_CHILD=1", "PMEQ_LEDGER_DIR="+d)
	if b, e := c.CombinedOutput(); e != nil {
		t.Fatal(string(b), e)
	}
	if e := ClaimPersistent(d, [16]byte{2}); e != nil {
		t.Fatal(e)
	}
}
