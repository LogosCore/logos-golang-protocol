package protocol

import "fmt"

// Max tasks (docs: contracts/minion-messages/tasks-and-results/, Max
// tasks): how many tasks a minion runs at once. A minion says how many it
// takes with each get_tasks (through a call, the room it has left; on a
// persistent connection, a standing allowance of its limit), and may say
// its limit in its hello (HelloItem.MaxTasks). Its factory either sets the
// limit itself (one at a time, say), or declares BuildSchema.MaxTasks: the
// build's limit is built in (BuildRequest.MaxTasks), and core changes it
// live with a max_tasks item, which goes in any message, whatever the
// minion runs: as a cancel does, and unlike a task, which would wait for a
// free slot, and could never undo a limit of 0. The minion answers with a
// max_tasks of its own, saying what its limit is now, and its get_tasks
// follow it. 0 takes no new tasks: the minion pauses, its running tasks
// going on. Core sends a max_tasks only to a minion of a factory that
// declares it, and a few times at most unanswered.

// MaxTasksItem is a minion's limit of tasks at once: core → minion, the
// limit to have; minion → core, the limit it has (in answer to core's, or
// on its own).
type MaxTasksItem struct {
	T   int    `cbor:"0,keyasint"`
	Max uint64 `cbor:"1,keyasint"`
}

const (
	// DefaultMaxTasks is a build's limit where the operator set none.
	DefaultMaxTasks = 5
	// MaxTasksLimit is the most a limit may be.
	MaxTasksLimit = 64
)

// Validate checks the limit.
func (m MaxTasksItem) Validate() error {
	if m.Max > MaxTasksLimit {
		return fmt.Errorf("max_tasks: %d at most", MaxTasksLimit)
	}
	return nil
}
