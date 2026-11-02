package protocol

import (
	"fmt"
	"time"
)

// Failover (docs: contracts/channel-core-connections/, Failover): how a
// minion built with several connections moves on its own when the one in
// use keeps failing. Core sends it with every build (BuildRequest.Failover,
// defaults filled in) and each connection's overrides
// (BuildConnection.Failover); a factory whose schema declares
// BuildSchema.Failover builds them into its minions, any other may ignore
// them. A minion reports each move in a conn_update, with why.
//
// A failure is an exchange with no usable reply: none, a timeout, a TLS or
// HTTP error, a WebSocket that does not open, a reply that does not open.
// A reply saying the session is closed is core's answer, not one.

// BuildFailover is a build's failover policy, over its connections in their
// order.
type BuildFailover struct {
	// Enabled: the minion moves on its own. Off, only an operator's switch
	// moves it.
	Enabled bool `json:"enabled"`
	// FailAfter is how many exchanges in a row must fail on a connection
	// before the minion moves (a connection's own FailAfter overrides it).
	FailAfter int `json:"fail_after"`
	// FailFor is how long the connection must also have been failing, from
	// the first of those failures: a quick burst of retries does not move
	// the minion. "0s": the count alone decides.
	FailFor string `json:"fail_for"`
	// Wrap: after the last connection, the first again. Off, the minion
	// stays on the last and keeps trying it.
	Wrap bool `json:"wrap"`
	// CyclePause is how long the minion waits once every connection it may
	// move to has failed in a row, before the next round.
	CyclePause string `json:"cycle_pause"`
	// FailbackAfter is how long the minion stays on a connection after the
	// first it may use before trying that first one again, once: back to it
	// when it answers, another FailbackAfter where it is when not. "0s":
	// never on its own.
	FailbackAfter string `json:"failback_after"`
}

// ConnectionFailover is a connection's own failover settings.
type ConnectionFailover struct {
	// Auto: failover may move the minion to it. Unset: true, but false for
	// a bind-persistent connection (core has to dial it: an operator's
	// switch, with a target).
	Auto *bool `json:"auto,omitempty"`
	// FailAfter, when set, replaces the build's for this connection.
	FailAfter int `json:"fail_after,omitempty"`
}

// Failover limits.
const (
	MaxFailAfter     = 1000
	MaxFailFor       = 24 * time.Hour
	MaxCyclePause    = 24 * time.Hour
	MaxFailbackAfter = 7 * 24 * time.Hour
)

// DefaultBuildFailover is the policy a build gets when its operator sets
// none: move after 5 failures in a row, round the list, pause 5 minutes
// after a round that all failed, and try the first connection again after
// an hour away from it.
func DefaultBuildFailover() BuildFailover {
	return BuildFailover{Enabled: true, FailAfter: 5, FailFor: "0s", Wrap: true, CyclePause: "5m", FailbackAfter: "1h"}
}

// Durations are the policy's durations, parsed; zero for one that does not
// parse (Validate refuses it).
func (f BuildFailover) Durations() (failFor, cyclePause, failbackAfter time.Duration) {
	parse := func(s string) time.Duration {
		d, _ := time.ParseDuration(s)
		return d
	}
	return parse(f.FailFor), parse(f.CyclePause), parse(f.FailbackAfter)
}

// Validate reports the policy's problems by key ("fail_after", ...); nil
// for none.
func (f BuildFailover) Validate() map[string]string {
	problems := map[string]string{}
	if f.FailAfter < 1 || f.FailAfter > MaxFailAfter {
		problems["fail_after"] = fmt.Sprintf("must be 1 to %d", MaxFailAfter)
	}
	for _, d := range []struct {
		key, value string
		max        time.Duration
	}{{"fail_for", f.FailFor, MaxFailFor}, {"cycle_pause", f.CyclePause, MaxCyclePause}, {"failback_after", f.FailbackAfter, MaxFailbackAfter}} {
		v, err := time.ParseDuration(d.value)
		switch {
		case err != nil:
			problems[d.key] = fmt.Sprintf("%q is not a duration (5m, 1h, 0s)", d.value)
		case v < 0 || v > d.max:
			problems[d.key] = fmt.Sprintf("must be 0s to %s", d.max)
		}
	}
	if len(problems) == 0 {
		return nil
	}
	return problems
}

// Validate reports a connection's failover problems by key; nil for none.
func (c ConnectionFailover) Validate() map[string]string {
	if c.FailAfter < 0 || c.FailAfter > MaxFailAfter {
		return map[string]string{"fail_after": fmt.Sprintf("must be 1 to %d, or unset for the build's", MaxFailAfter)}
	}
	return nil
}

// FailoverAuto reports whether failover may move a minion to c.
func (c BuildConnection) FailoverAuto() bool {
	if c.Failover != nil && c.Failover.Auto != nil {
		return *c.Failover.Auto
	}
	return c.ConnectionKind() != KindBindPersistent
}

// FailAfter is how many failures in a row move a minion off c under f.
func (c BuildConnection) FailAfter(f BuildFailover) int {
	if c.Failover != nil && c.Failover.FailAfter > 0 {
		return c.Failover.FailAfter
	}
	return f.FailAfter
}
