package protocol

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDefaultBuildFailover(t *testing.T) {
	f := DefaultBuildFailover()
	if f.Validate() != nil || !f.Enabled || f.FailAfter != 5 || !f.Wrap {
		t.Fatalf("%+v: %v", f, f.Validate())
	}
	failFor, pause, back := f.Durations()
	if failFor != 0 || pause != 5*time.Minute || back != time.Hour {
		t.Fatalf("durations %s %s %s", failFor, pause, back)
	}
}

func TestBuildFailoverRefused(t *testing.T) {
	for key, mutate := range map[string]func(f *BuildFailover){
		"fail_after":     func(f *BuildFailover) { f.FailAfter = 0 },
		"fail_for":       func(f *BuildFailover) { f.FailFor = "soon" },
		"cycle_pause":    func(f *BuildFailover) { f.CyclePause = "25h" },
		"failback_after": func(f *BuildFailover) { f.FailbackAfter = "-1m" },
	} {
		f := DefaultBuildFailover()
		mutate(&f)
		if p := f.Validate(); p[key] == "" || len(p) != 1 {
			t.Errorf("%s: %v", key, p)
		}
	}
	if (ConnectionFailover{FailAfter: MaxFailAfter + 1}).Validate() == nil || (ConnectionFailover{}).Validate() != nil {
		t.Error("a connection's fail_after")
	}
}

// A listening connection is left out of failover unless it says otherwise;
// a connection's fail_after replaces the build's.
func TestConnectionFailover(t *testing.T) {
	on, off := true, false
	conn := func(kind string, f *ConnectionFailover) BuildConnection {
		return BuildConnection{Endpoint: ChannelEndpointExport{Kind: kind}, Failover: f}
	}
	if !conn(KindReverseCall, nil).FailoverAuto() || conn(KindBindPersistent, nil).FailoverAuto() ||
		!conn(KindBindPersistent, &ConnectionFailover{Auto: &on}).FailoverAuto() || conn(KindReverseCall, &ConnectionFailover{Auto: &off}).FailoverAuto() {
		t.Error("auto")
	}
	f := DefaultBuildFailover()
	if conn(KindReverseCall, nil).FailAfter(f) != 5 || conn(KindReverseCall, &ConnectionFailover{FailAfter: 2}).FailAfter(f) != 2 {
		t.Error("fail_after")
	}
	// As JSON: snake_case keys, and a connection without overrides says none.
	b, _ := json.Marshal(BuildRequest{Failover: &f, Connections: []BuildConnection{conn(KindReverseCall, nil)}})
	var back struct {
		Failover    map[string]any   `json:"failover"`
		Connections []map[string]any `json:"connections"`
	}
	_ = json.Unmarshal(b, &back)
	if back.Failover["failback_after"] != "1h" || back.Connections[0]["failover"] != nil {
		t.Fatalf("%s", b)
	}
}
