package protocol

import (
	"strings"
	"testing"
)

func TestMachineID(t *testing.T) {
	if got := MachineID(MachineSMBIOSUUID, " 4C4C4544-0042-1010-8048-B7C04F4D3132\n"); got != "smbios-uuid:4c4c4544-0042-1010-8048-b7c04f4d3132" {
		t.Errorf("MachineID: %q", got)
	}
	for _, ok := range []string{"linux-machine-id:5f3e9a00aa", "hostname:work", "acme-tpm:ab12", "domain-sid:s-1-5-21-1-2-3-1001"} {
		if err := ValidateMachineID(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for bad, want := range map[string]string{
		"nocolon":                       "<source>:<value>",
		"Linux:abc":                     "source",
		"hostname:":                     "no value",
		"hostname:my host":              "space",
		"x:" + strings.Repeat("a", 300): "too long",
	} {
		if err := ValidateMachineID(bad); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", bad, err, want)
		}
	}
	// A hello without one passes (minions built before it); a bad one does not.
	if (HelloItem{PID: 1, OS: "linux", Arch: "amd64"}).Validate() != nil {
		t.Error("a hello without machine_id")
	}
	if (HelloItem{PID: 1, OS: "linux", Arch: "amd64", MachineID: "bad"}).Validate() == nil {
		t.Error("a bad machine_id passed")
	}
}

func TestPlaceholderMachineUUID(t *testing.T) {
	for _, p := range []string{"", "00000000-0000-0000-0000-000000000000", "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
		"03000200-0400-0500-0006-000700080009", "To Be Filled By O.E.M.", "Default string", "Not Settable"} {
		if !PlaceholderMachineUUID(p) {
			t.Errorf("%q is a placeholder", p)
		}
	}
	if PlaceholderMachineUUID("4c4c4544-0042-1010-8048-b7c04f4d3132") {
		t.Error("a real UUID taken for a placeholder")
	}
}
