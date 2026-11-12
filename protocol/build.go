package protocol

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// This file defines the build schema: what a factory can build and which
// parameters each build takes. A factory declares it at module.register under
// "build", the way a channel declares its connection schema (connection.go).
// Operators fill it in, core validates their values and sends factory.build
// requests (build_ops.go) that follow it.
//
// A schema lists targets (what the factory can produce: a format, the
// platforms it runs on, its own fields) next to the fields every target
// shares, the channel kinds its minions speak, with the factory's own
// connection parameters for each, the payload crypto suites they implement,
// and the commands they can be built with, from which operators pick each
// build's. Values are validated with the same FieldSpec rules as management
// properties.

// BuildSchemaV3 is the current build schema format version: commands and
// their params numbered (BuildCommand.Op, FieldSpec.Num), and channels by
// connection kind, each with the factory's own parameters (BuildChannel).
// "1" and "2" are no longer taken.
const BuildSchemaV3 = "3"

// MaxCommandNumber bounds a command's op and a param's num.
const MaxCommandNumber = 1<<16 - 1

// RegisterFieldBuild is the module.register key a factory declares its build
// schema under.
const RegisterFieldBuild = "build"

// Build schema limits.
const (
	MaxBuildTargets         = 32
	MaxBuildTargetFields    = 64 // shared fields plus the target's own
	MaxBuildPlatforms       = 16 // per target
	MaxBuildChannels        = 16
	MaxBuildChannelVersions = 16 // per channel kind
	MaxConnectionParams     = 32 // per channel kind
	MaxBuildCommands        = 256
	MaxCommandParams        = 32 // per command
)

// MaxErrorCode is the highest of a factory's error codes (ErrorCode): an
// exit code every OS keeps whole, a Unix process's being a byte.
const MaxErrorCode = 255

var (
	// targetIDPattern is also what a target's format must match.
	targetIDPattern    = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
	platformPattern    = regexp.MustCompile(`^[a-z0-9]{1,31}/[a-z0-9]{1,31}$`)
	cryptoSuitePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	// commandIDPattern is a target id's: no dots, so a command's id can key a
	// document.
	commandIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
	// moduleNamePattern: core only requires a module name, so a factory can
	// name any channel kind that registers.
	moduleNamePattern = regexp.MustCompile(`^\S{1,64}$`)
)

// BuildSchema is declared by a factory in module.register under "build".
type BuildSchema struct {
	// SchemaVersion is the format of this structure (BuildSchemaV1).
	SchemaVersion string `json:"schema_version"`
	// Version is the version of the factory's parameter set, starting at 1.
	// A factory raises it when values saved against the previous set would
	// build something else or fail (a field or target removed, renamed or
	// given a new meaning). Adding an optional field or a target does not
	// need a new version.
	Version  int            `json:"version"`
	Channels []BuildChannel `json:"channels"`
	// Crypto is the payload crypto suite the minions implement: core's
	// (CoreSuites), whose keys core makes, or the factory's own,
	// "<module_name>.<name>", which the factory translates and makes the
	// keys of (codecs.go). Optional; core refuses a registration naming a
	// suite it does not implement, or another module's.
	Crypto string `json:"crypto,omitempty"`
	// Envelope is how the minions write a message as plaintext: core's
	// (CoreEnvelopes), EnvelopeCBOR when none, or the factory's own,
	// "<module_name>.<name>", which the factory translates.
	Envelope string `json:"envelope,omitempty"`
	// Codec is what the factory declares of the layers it translates:
	// required when the schema or a target names a suite or an envelope
	// of the factory's own, refused otherwise.
	Codec *BuildCodec `json:"codec,omitempty"`
	// Fields are the build parameters every target shares.
	Fields  []FieldSpec   `json:"fields,omitempty"`
	Targets []BuildTarget `json:"targets"`
	// Commands are what the minions can do. An operator picks a build's
	// from those of its target, and the minion has only those. Optional: a
	// factory without commands builds minions with none.
	Commands []BuildCommand `json:"commands,omitempty"`
	// ErrorCodes are the factory's own: what a minion's exit code means when
	// it stops on an error (a config it cannot read, no connection it can
	// use), for an operator to look up (error_codes.go). Optional; core
	// shows them with the factory and its builds, and does nothing else with
	// them.
	ErrorCodes []ErrorCode `json:"error_codes,omitempty"`
	// ErrorCodesPerBuild says the minions exit with the codes each build
	// gives them (BuildRequest.ErrorCodes): core draws one for every
	// declared code that is not Fixed (DrawErrorCodes) unless the operator
	// turns that off, so two builds exit with different codes for the same
	// error. Needs a code that is not fixed. A factory that starts
	// declaring it raises Version: an instance that would ignore the codes
	// is never offered a build that carries them. Optional.
	ErrorCodesPerBuild bool `json:"error_codes_per_build,omitempty"`
	// PersistedSessions says the minions can claim a persisted session:
	// built with a BuildRequest.SessionID, they claim it in their hello
	// (HelloItem.SID). Optional.
	PersistedSessions bool `json:"persisted_sessions,omitempty"`
	// Failover says the minions honor a build's failover settings
	// (BuildRequest.Failover, BuildConnection.Failover): they move between
	// their connections on their own as those say. Optional: without it,
	// the settings still reach the factory, which may ignore them.
	Failover bool `json:"failover,omitempty"`
	// MaxTasks says the minions' limit of tasks at once is the operators'
	// to set: the build's (BuildRequest.MaxTasks) as they start, which
	// core changes live (MaxTasksItem); they say it in their hello.
	// Optional: without it, a build has no max_tasks, and a minion runs as
	// many as its factory made it (one at a time, say), which its hello may
	// report but core never changes.
	MaxTasks bool `json:"max_tasks,omitempty"`
	// Compression are the algorithms the minions inflate (Compressions:
	// CompressionDeflate): core packs items for a minion of a build with
	// compression on (BuildRequest.Compression), on by default, and the
	// minion may pack its own. Optional: without it, core packs nothing
	// for its minions.
	Compression []string `json:"compression,omitempty"`
	// MinionConfig asks core for each build's settings numbered, as a minion
	// reads them: a minion config (minion_config.go) with each build request
	// (BuildRequest.MinionConfig), numbered CBOR for the factory to use as it
	// decides. Every channel, field and connection parameter is numbered, in
	// every schema (BuildChannel.Num, FieldSpec.Num), so core can make a
	// config for any build. Optional.
	MinionConfig bool `json:"minion_config,omitempty"`
}

// ErrorCode is one of a factory's error codes (BuildSchema.ErrorCodes).
type ErrorCode struct {
	// Code is the number, 1 to MaxErrorCode, once in the schema: a minion's
	// exit code. 0 is success. A runtime's own may be declared too, to say
	// what they mean for the factory's minions: Go exits with 2 on a panic,
	// and shells report a process a signal killed as 128 and its number.
	Code int `json:"code"`
	// Label says what it means, in a few words. Required.
	Label string `json:"label"`
	// Description says more: when it happens, what to do. Optional.
	Description string `json:"description,omitempty"`
	// Fixed says the code is the same in every build, for a schema that
	// declares ErrorCodesPerBuild: core draws none for it, and draws it for
	// no other code. A runtime's own (Go's 2), or one the minions cannot
	// change.
	Fixed bool `json:"fixed,omitempty"`
}

// ChannelVersions is a channel kind (its module_name), the connection
// schema versions a factory's minions read, and the connection kinds they
// support through it, by name, in the factory's order: what a target
// narrows the factory's channels to (BuildTarget.Channels).
type ChannelVersions struct {
	ModuleName string   `json:"module_name"`
	Versions   []int    `json:"versions"`
	Kinds      []string `json:"kinds,omitempty"`
}

// BuildChannel is a channel kind the minions speak: the connection schema
// versions they read, and the connection kinds they support through it, in
// the factory's order of preference (a build that names none takes the
// first one the channel carries too).
type BuildChannel struct {
	ModuleName string `json:"module_name"`
	// Num is the channel's number in a minion config
	// (MinionConnection.Channel), 1 to MaxFieldNumber, once in the schema,
	// required: a minion reading a config needs no channel names.
	Num      int         `json:"num,omitempty"`
	Versions []int       `json:"versions"`
	Kinds    []BuildKind `json:"kinds"`
}

// BuildKind is a connection kind a factory's minions support through a
// channel, with Fields, the factory's connection parameters for it: how its
// minions use the channel that way (e.g. the HTTP method of a request), set
// for each connection of a build. Two kinds that share a parameter each
// declare it.
type BuildKind struct {
	Kind   string      `json:"kind"`
	Fields []FieldSpec `json:"fields,omitempty"`
}

// KindNames are the channel's kinds, by name, in the factory's order.
func (c BuildChannel) KindNames() []string {
	out := make([]string, len(c.Kinds))
	for i, k := range c.Kinds {
		out[i] = k.Kind
	}
	return out
}

// KindFields are the factory's connection parameters for kind; none for a
// kind it does not list.
func (c BuildChannel) KindFields(kind string) []FieldSpec {
	for _, k := range c.Kinds {
		if k.Kind == kind {
			return k.Fields
		}
	}
	return nil
}

// BuildTarget is something a factory can produce.
type BuildTarget struct {
	ID          string `json:"id"`
	Label       string `json:"label,omitempty"`
	Description string `json:"description,omitempty"`
	// Format is what the artifact is (exe, dll, elf, so, macho, dylib, bin,
	// script, zip, ...): shown and filtered on, never interpreted.
	Format string `json:"format"`
	// Platforms are where the artifact runs, as "os/arch" with Go's names;
	// "any" stands for either half.
	Platforms []string `json:"platforms"`
	// Fields are this target's own parameters, after the shared ones.
	Fields []FieldSpec `json:"fields,omitempty"`
	// Channels narrows the factory's channels for this target, to channels,
	// versions and connection kinds the factory lists; empty means all of
	// them, and an entry without kinds all of the channel's. The connection
	// parameters stay the factory's.
	Channels []ChannelVersions `json:"channels,omitempty"`
	// Opens narrows what this target's tunnel commands open (their Opens),
	// for a platform that has less (a Linux build has no named pipes):
	// empty means all of them (CommandOpens).
	Opens []string `json:"opens,omitempty"`
	// Crypto and Envelope replace the schema's for this target's builds
	// (BuildSchema.TargetCodec): one factory may build a minion in a
	// compiled language and one in a script.
	Crypto   string `json:"crypto,omitempty"`
	Envelope string `json:"envelope,omitempty"`
}

// BuildCommand is a command a factory's minions can be built with. An
// operator picks a build's commands, so a minion carries only what its job
// needs.
type BuildCommand struct {
	// ID names the command in builds and in core, unique in the schema:
	// ^[a-z][a-z0-9_-]{0,62}$.
	ID string `json:"id"`
	// Op is the command's number, unique in the schema, 1 to
	// MaxCommandNumber: a task names its command by it on the wire
	// (TaskItem.Cmd), so a minion needs no command names. Its params are
	// numbered too (FieldSpec.Num).
	Op          int    `json:"op"`
	Label       string `json:"label,omitempty"`
	Description string `json:"description,omitempty"`
	// Targets narrows the command to these targets; empty means all of them.
	Targets []string `json:"targets,omitempty"`
	// Default commands are picked in a new build until the operator unpicks
	// them, and a build that names no commands gets them.
	Default bool `json:"default,omitempty"`
	// Required commands are in every build of a target that has them: the
	// minion cannot run without them (sleep, exit), so the operator cannot
	// leave them out.
	Required bool `json:"required,omitempty"`
	// Params are what a task of the command takes: field specs as a
	// management action's, file aside.
	Params []FieldSpec `json:"params,omitempty"`
	// Result is what the command's data is: one of core's results
	// (ResultDirListing), which says its shape and how it is shown; empty:
	// no declared shape, shown raw (task_results.go).
	Result string `json:"result,omitempty"`
	// Action is what core can ask the command to do itself: one of core's
	// actions (ActionListDir), which says the params it gives and the
	// result it needs; empty: core never runs it on its own.
	Action string `json:"action,omitempty"`
	// Kinds narrows the command to sessions whose minion uses a connection
	// of these kinds (KindReversePersistent, ...); empty: every kind. For a
	// command that does not work, or not well, over the others (an
	// interactive shell needs a connection either side can speak on at
	// once): core refuses a task of it on a session on another kind.
	Kinds []string `json:"kinds,omitempty"`
	// Opens is what a tunnel command's minion opens, and how: TCP
	// connections and UDP associations (a tunnel), or a TCP or UDP listener
	// (a reverse tunnel); a tunnel's unix sockets and named pipes
	// (OpenUnix, OpenPipe), its connections from a source address
	// (OpenSource) and TLS to the destination (OpenTLS). Empty: TCP alone.
	// Core opens nothing else through it: a SOCKS UDP ASSOCIATE through a
	// command that opens no udp is refused at once. Only a tunnel command
	// says it (CanOpen); a target may narrow it (BuildTarget.Opens).
	Opens []string `json:"opens,omitempty"`
	// Serves are the channel kinds a delegate command's minion serves
	// (delegation.go): the channel's side of each transport, for the
	// minions of its operation, while its task runs. Bind kinds for
	// ActionDelegate, reverse ones for ActionReverseDelegate; only a
	// delegate command says it, and one must. A factory that serves other
	// kinds on another target declares another command (Targets).
	Serves []ChannelVersions `json:"serves,omitempty"`
}

// CanOpen reports whether the command's minion opens kind (OpenTCP,
// OpenUDP): one of its Opens, or TCP when it says none.
func (c BuildCommand) CanOpen(kind string) bool {
	if len(c.Opens) == 0 {
		return kind == OpenTCP
	}
	return slices.Contains(c.Opens, kind)
}

// CommandOpens is what c's minion opens in a build of target id: its
// Opens (TCP alone when it says none), narrowed by the target's Opens.
func (s BuildSchema) CommandOpens(c BuildCommand, target string) []string {
	out := c.Opens
	if len(out) == 0 {
		out = []string{OpenTCP}
	}
	t, ok := s.Target(target)
	if !ok || len(t.Opens) == 0 {
		return slices.Clone(out)
	}
	var narrowed []string
	for _, o := range out {
		if slices.Contains(t.Opens, o) {
			narrowed = append(narrowed, o)
		}
	}
	return narrowed
}

// For reports whether a build of target id can have the command.
func (c BuildCommand) For(id string) bool {
	return len(c.Targets) == 0 || slices.Contains(c.Targets, id)
}

// OverKind reports whether a task of the command can go to a minion on a
// connection of kind.
func (c BuildCommand) OverKind(kind string) bool {
	return len(c.Kinds) == 0 || slices.Contains(c.Kinds, kind)
}

// Target returns the target with id, if declared.
func (s BuildSchema) Target(id string) (BuildTarget, bool) {
	for _, t := range s.Targets {
		if t.ID == id {
			return t, true
		}
	}
	return BuildTarget{}, false
}

// Channel returns the factory's entry for a channel kind, if declared.
func (s BuildSchema) Channel(moduleName string) (BuildChannel, bool) {
	for _, c := range s.Channels {
		if c.ModuleName == moduleName {
			return c, true
		}
	}
	return BuildChannel{}, false
}

// TargetFields returns the fields a build of t takes: the shared ones, then
// the target's own.
func (s BuildSchema) TargetFields(t BuildTarget) []FieldSpec {
	out := make([]FieldSpec, 0, len(s.Fields)+len(t.Fields))
	return append(append(out, s.Fields...), t.Fields...)
}

// TargetChannels returns the channel kinds and versions a build of t can
// connect through.
func (s BuildSchema) TargetChannels(t BuildTarget) []ChannelVersions {
	if len(t.Channels) > 0 {
		return t.Channels
	}
	out := make([]ChannelVersions, len(s.Channels))
	for i, c := range s.Channels {
		out[i] = ChannelVersions{ModuleName: c.ModuleName, Versions: c.Versions, Kinds: c.KindNames()}
	}
	return out
}

// TargetKinds are the connection kinds a build of t supports through channel
// moduleName, in the factory's order: the target's entry's when it lists
// any, else the factory's. None when t cannot connect through it.
func (s BuildSchema) TargetKinds(t BuildTarget, moduleName string) []string {
	for _, c := range t.Channels {
		if c.ModuleName == moduleName && len(c.Kinds) > 0 {
			return c.Kinds
		}
	}
	for _, c := range s.TargetChannels(t) {
		if c.ModuleName == moduleName {
			if ch, ok := s.Channel(moduleName); ok {
				return ch.KindNames()
			}
		}
	}
	return nil
}

// UsableKinds are the kinds both sides support: those of factory (in its
// order) the channel carries too.
func UsableKinds(factory, channel []string) []string {
	var out []string
	for _, k := range factory {
		if slices.Contains(channel, k) {
			out = append(out, k)
		}
	}
	return out
}

// Supports reports whether a build of t can connect through channel kind
// moduleName, whose connection schema is at version.
func (s BuildSchema) Supports(t BuildTarget, moduleName string, version int) bool {
	for _, c := range s.TargetChannels(t) {
		if c.ModuleName == moduleName {
			return slices.Contains(c.Versions, version)
		}
	}
	return false
}

// Command returns the command with id, if declared.
func (s BuildSchema) Command(id string) (BuildCommand, bool) {
	for _, c := range s.Commands {
		if c.ID == id {
			return c, true
		}
	}
	return BuildCommand{}, false
}

// TargetCommands returns the commands a build of t can have, in the schema's
// order.
func (s BuildSchema) TargetCommands(t BuildTarget) []BuildCommand {
	var out []BuildCommand
	for _, c := range s.Commands {
		if c.For(t.ID) {
			out = append(out, c)
		}
	}
	return out
}

// DefaultCommands returns the ids of the commands a build of t gets when it
// names none: its default and required ones, in the schema's order.
func (s BuildSchema) DefaultCommands(t BuildTarget) []string {
	out := []string{}
	for _, c := range s.TargetCommands(t) {
		if c.Default || c.Required {
			out = append(out, c.ID)
		}
	}
	return out
}

// HasPlatform reports whether t runs on platform.
func (t BuildTarget) HasPlatform(platform string) bool {
	return slices.Contains(t.Platforms, platform)
}

// ValidateBuildSchema checks a schema's structure, limits, and that every
// declared default satisfies its own field spec.
func ValidateBuildSchema(s BuildSchema) error {
	if s.SchemaVersion != BuildSchemaV3 {
		return fmt.Errorf("unsupported build schema_version %q", s.SchemaVersion)
	}
	if s.Version < 1 {
		return fmt.Errorf("version must be at least 1")
	}
	if len(s.Channels) == 0 {
		return fmt.Errorf("at least one channel is required")
	}
	if len(s.Channels) > MaxBuildChannels {
		return fmt.Errorf("too many channels (%d > %d)", len(s.Channels), MaxBuildChannels)
	}
	channels := make(map[string]ChannelVersions, len(s.Channels))
	channelNums := map[int]string{}
	for _, c := range s.Channels {
		cv := ChannelVersions{ModuleName: c.ModuleName, Versions: c.Versions, Kinds: c.KindNames()}
		if err := validateChannelVersions(cv); err != nil {
			return fmt.Errorf("channel %q: %w", c.ModuleName, err)
		}
		if len(c.Kinds) == 0 {
			return fmt.Errorf("channel %q: at least one connection kind", c.ModuleName)
		}
		if _, dup := channels[c.ModuleName]; dup {
			return fmt.Errorf("duplicate channel %q", c.ModuleName)
		}
		channels[c.ModuleName] = cv
		switch {
		case c.Num == 0:
			return fmt.Errorf("channel %q: a num is required (its number in a minion config)", c.ModuleName)
		case c.Num < 0 || c.Num > MaxFieldNumber:
			return fmt.Errorf("channel %q: num must be 1 to %d", c.ModuleName, MaxFieldNumber)
		case c.Num != 0:
			if other, dup := channelNums[c.Num]; dup {
				return fmt.Errorf("channel %q: num %d is %q's", c.ModuleName, c.Num, other)
			}
			channelNums[c.Num] = c.ModuleName
		}
		kindFields := make([][]FieldSpec, 0, len(c.Kinds))
		for _, k := range c.Kinds {
			if len(k.Fields) > MaxConnectionParams {
				return fmt.Errorf("channel %q kind %s: too many connection parameters (%d > %d)", c.ModuleName, k.Kind,
					len(k.Fields), MaxConnectionParams)
			}
			if _, err := validateBuildFields(k.Fields, nil); err != nil {
				return fmt.Errorf("channel %q kind %s: %w", c.ModuleName, k.Kind, err)
			}
			kindFields = append(kindFields, k.Fields)
		}
		if err := checkFieldNumbers(kindFields...); err != nil {
			return fmt.Errorf("channel %q: %w", c.ModuleName, err)
		}
	}

	for i, c := range s.Compression {
		if !IsCompression(c) {
			return fmt.Errorf("compression %q: the protocol has %v", c, Compressions)
		}
		if slices.Contains(s.Compression[:i], c) {
			return fmt.Errorf("compression %q named twice", c)
		}
	}

	if len(s.Fields) > MaxBuildTargetFields {
		return fmt.Errorf("too many fields (%d > %d)", len(s.Fields), MaxBuildTargetFields)
	}
	shared, err := validateBuildFields(s.Fields, nil)
	if err != nil {
		return err
	}

	if len(s.Targets) == 0 {
		return fmt.Errorf("at least one target is required")
	}
	if len(s.Targets) > MaxBuildTargets {
		return fmt.Errorf("too many targets (%d > %d)", len(s.Targets), MaxBuildTargets)
	}
	ids := make(map[string]bool, len(s.Targets))
	fieldGroups := [][]FieldSpec{s.Fields}
	for _, t := range s.Targets {
		if err := validateBuildTarget(t, shared, channels); err != nil {
			return fmt.Errorf("target %q: %w", t.ID, err)
		}
		if ids[t.ID] {
			return fmt.Errorf("duplicate target %q", t.ID)
		}
		ids[t.ID] = true
		fieldGroups = append(fieldGroups, t.Fields)
	}
	if err := checkFieldNumbers(fieldGroups...); err != nil {
		return err
	}

	if err := validateCodecs(s); err != nil {
		return err
	}

	if len(s.Commands) > MaxBuildCommands {
		return fmt.Errorf("too many commands (%d > %d)", len(s.Commands), MaxBuildCommands)
	}
	commands := make(map[string]bool, len(s.Commands))
	ops := make(map[int]string, len(s.Commands))
	declared := map[string]bool{}
	for _, c := range s.Channels {
		for _, k := range c.KindNames() {
			declared[k] = true
		}
	}
	for _, c := range s.Commands {
		if err := validateBuildCommand(c, ids); err != nil {
			return fmt.Errorf("command %q: %w", c.ID, err)
		}
		for _, k := range c.Kinds {
			if !declared[k] {
				return fmt.Errorf("command %q: kinds: the factory's minions connect through no %s connection", c.ID, k)
			}
		}
		if commands[c.ID] {
			return fmt.Errorf("duplicate command %q", c.ID)
		}
		commands[c.ID] = true
		if err := validateCommandNumbers(c); err != nil {
			return fmt.Errorf("command %q: %w", c.ID, err)
		}
		if other, dup := ops[c.Op]; dup {
			return fmt.Errorf("command %q: op %d is %q's", c.ID, c.Op, other)
		}
		ops[c.Op] = c.ID
	}
	return validateErrorCodes(s)
}

// CommandHelp is core's own command, in every session's console: it lists
// the commands the session's minion takes, or one command's params. Core
// answers it; it never goes to a minion, and a schema may not declare it.
const CommandHelp = "help"

// CommandConnect and CommandDisconnect are core's own commands in the
// console of a session whose connection is bind-persistent: they open and
// close its target's connection (core asks the channel to dial the minion,
// or closes the connection's socket). Core runs them and keeps them as
// tasks; they never go to a minion (a minion not connected could not get
// one), and a schema may not declare them.
const (
	CommandConnect    = "connect"
	CommandDisconnect = "disconnect"
)

// CommandMaxTasks is core's own command in the console of a session whose
// build's factory declares BuildSchema.MaxTasks: it sets how many tasks the
// minion runs at once (its param max, 0 to MaxTasksLimit), as the session's
// Tasks do. Core runs it and keeps it as a task, which ends when the minion
// says it has the limit (MaxTasksItem), or when it does not take it; it
// never goes to a minion as a task, and a schema may not declare it.
const CommandMaxTasks = "max_tasks"

// CoreCommands are core's own commands: core runs them, they never go to a
// minion as tasks, and a build schema may not declare them.
func CoreCommands() []string {
	return []string{CommandHelp, CommandConnect, CommandDisconnect, CommandMaxTasks}
}

// IsCoreCommand reports whether id is one of core's own commands, which a
// build schema may not declare.
func IsCoreCommand(id string) bool {
	return slices.Contains(CoreCommands(), id)
}

// validateCommandNumbers checks a command's op and its params' nums: each 1
// to MaxCommandNumber, the nums once each; none for a param that is core's
// alone (one its action adds), which never goes to the minion.
func validateCommandNumbers(c BuildCommand) error {
	if c.Op < 1 || c.Op > MaxCommandNumber {
		return fmt.Errorf("op must be 1 to %d", MaxCommandNumber)
	}
	nums := make(map[int]string, len(c.Params))
	for _, p := range c.Params {
		if IsCoreParam(c.Action, p.Key) {
			if p.Num != 0 {
				return fmt.Errorf("param %q is core's alone (%s): it takes no num, and never goes to the minion", p.Key, c.Action)
			}
			continue
		}
		if p.Num < 1 || p.Num > MaxCommandNumber {
			return fmt.Errorf("param %q: num must be 1 to %d", p.Key, MaxCommandNumber)
		}
		if other, dup := nums[p.Num]; dup {
			return fmt.Errorf("param %q: num %d is %q's", p.Key, p.Num, other)
		}
		nums[p.Num] = p.Key
	}
	return nil
}

// validateBuildCommand checks a command; targets are the schema's target ids.
func validateBuildCommand(c BuildCommand, targets map[string]bool) error {
	if !commandIDPattern.MatchString(c.ID) {
		return fmt.Errorf("id must match %s", commandIDPattern)
	}
	if IsCoreCommand(c.ID) {
		return fmt.Errorf("%q is core's own command: a factory does not declare it", c.ID)
	}
	if err := validateText(c.Label, c.Description); err != nil {
		return err
	}
	if err := validateResultAction(c); err != nil {
		return err
	}
	for i, t := range c.Targets {
		if !targets[t] {
			return fmt.Errorf("target %q is not one the factory lists", t)
		}
		if slices.Contains(c.Targets[:i], t) {
			return fmt.Errorf("duplicate target %q", t)
		}
	}
	for i, k := range c.Kinds {
		if !KnownKind(k) {
			return fmt.Errorf("kinds: %q is not a connection kind", k)
		}
		if slices.Contains(c.Kinds[:i], k) {
			return fmt.Errorf("kinds: duplicate %q", k)
		}
	}
	if len(c.Opens) > 0 && !IsTunnelAction(c.Action) {
		return fmt.Errorf("opens: only a tunnel command (%s) says what it opens", strings.Join(TunnelActions(), ", "))
	}
	for i, o := range c.Opens {
		if allowed := opensOf(c.Action); !slices.Contains(allowed, o) {
			return fmt.Errorf("opens: %q is not one of %s", o, strings.Join(allowed, ", "))
		}
		if slices.Contains(c.Opens[:i], o) {
			return fmt.Errorf("opens: duplicate %q", o)
		}
	}
	if err := validateOpenParams(c); err != nil {
		return err
	}
	if err := validateServes(c); err != nil {
		return err
	}
	if len(c.Params) > MaxCommandParams {
		return fmt.Errorf("too many params (%d > %d)", len(c.Params), MaxCommandParams)
	}
	params := make(map[string]bool, len(c.Params))
	files := 0
	for _, p := range c.Params {
		p.Num = 0 // validateCommandNumbers checks it; checkFieldSpec refuses one elsewhere
		// A file param is a task file core sends the minion with the task
		// (docs: contracts/minion-messages.md, Core sending a file), a
		// stream param one core streams it as it is uploaded: one of either
		// a task at most.
		if err := checkCommandParam(p); err != nil {
			return fmt.Errorf("param %q: %w", p.Key, err)
		}
		if params[p.Key] {
			return fmt.Errorf("duplicate param %q", p.Key)
		}
		params[p.Key] = true
		if p.Type == FieldFile || p.Type == FieldStream {
			if files++; files > 1 {
				return fmt.Errorf("param %q: a command takes one file or stream param at most", p.Key)
			}
		}
	}
	// A condition may name a param core adds to the command's action (a
	// tunnel's front).
	return validateParamConditions(c.Params, actions[c.Action].Adds)
}

func validateChannelVersions(c ChannelVersions) error {
	if !moduleNamePattern.MatchString(c.ModuleName) {
		return fmt.Errorf("module_name must be 1..64 characters without spaces")
	}
	if len(c.Versions) == 0 || len(c.Versions) > MaxBuildChannelVersions {
		return fmt.Errorf("needs 1..%d versions", MaxBuildChannelVersions)
	}
	for i, v := range c.Versions {
		if v < 1 {
			return fmt.Errorf("versions start at 1")
		}
		if slices.Contains(c.Versions[:i], v) {
			return fmt.Errorf("duplicate version %d", v)
		}
	}
	for i, k := range c.Kinds {
		if !KnownKind(k) {
			return fmt.Errorf("kinds: %q is not a connection kind", k)
		}
		if slices.Contains(c.Kinds[:i], k) {
			return fmt.Errorf("duplicate kind %q", k)
		}
	}
	return nil
}

// checkFieldNumbers checks the numbers of fields read together (a schema's
// shared fields and its targets' own, a channel's kinds' fields): a number
// names one key, and a key numbered in two places has the same number in
// both. Each number's range is checkFieldSpec's.
func checkFieldNumbers(groups ...[]FieldSpec) error {
	keys := map[int]string{}
	nums := map[string]int{}
	for _, g := range groups {
		for _, f := range g {
			if f.Num == 0 {
				continue
			}
			if k, ok := keys[f.Num]; ok && k != f.Key {
				return fmt.Errorf("field %q: num %d is %q's", f.Key, f.Num, k)
			}
			if n, ok := nums[f.Key]; ok && n != f.Num {
				return fmt.Errorf("field %q: num %d here, %d elsewhere", f.Key, f.Num, n)
			}
			keys[f.Num], nums[f.Key] = f.Key, f.Num
		}
	}
	return nil
}

// validateBuildFields checks fields, and that their keys are unique, also
// against taken. It returns taken plus the new keys.
func validateBuildFields(fields []FieldSpec, taken map[string]bool) (map[string]bool, error) {
	keys := make(map[string]bool, len(taken)+len(fields))
	for k := range taken {
		keys[k] = true
	}
	for _, f := range fields {
		if err := validateBuildFieldSpec(f); err != nil {
			return nil, fmt.Errorf("field %q: %w", f.Key, err)
		}
		if err := notParam(f); err != nil {
			return nil, fmt.Errorf("field %q: %w", f.Key, err)
		}
		if f.Num == 0 {
			return nil, fmt.Errorf("field %q: a num is required (its number in a minion config)", f.Key)
		}
		if keys[f.Key] {
			return nil, fmt.Errorf("duplicate field key %q", f.Key)
		}
		keys[f.Key] = true
	}
	return keys, nil
}

func validateBuildTarget(t BuildTarget, shared map[string]bool, channels map[string]ChannelVersions) error {
	if !targetIDPattern.MatchString(t.ID) {
		return fmt.Errorf("id must match %s", targetIDPattern)
	}
	if err := validateText(t.Label, t.Description); err != nil {
		return err
	}
	if !targetIDPattern.MatchString(t.Format) {
		return fmt.Errorf("format must match %s", targetIDPattern)
	}
	if len(t.Platforms) == 0 || len(t.Platforms) > MaxBuildPlatforms {
		return fmt.Errorf("needs 1..%d platforms", MaxBuildPlatforms)
	}
	for i, p := range t.Platforms {
		if !platformPattern.MatchString(p) {
			return fmt.Errorf("platform %q must be os/arch, e.g. windows/amd64", p)
		}
		if slices.Contains(t.Platforms[:i], p) {
			return fmt.Errorf("duplicate platform %q", p)
		}
	}
	if len(shared)+len(t.Fields) > MaxBuildTargetFields {
		return fmt.Errorf("too many fields (%d with the shared ones > %d)", len(shared)+len(t.Fields), MaxBuildTargetFields)
	}
	if _, err := validateBuildFields(t.Fields, shared); err != nil {
		return err
	}
	for i, c := range t.Channels {
		if err := validateChannelVersions(c); err != nil {
			return fmt.Errorf("channel %q: %w", c.ModuleName, err)
		}
		declared, ok := channels[c.ModuleName]
		if !ok {
			return fmt.Errorf("channel %q is not one the factory lists", c.ModuleName)
		}
		for _, v := range c.Versions {
			if !slices.Contains(declared.Versions, v) {
				return fmt.Errorf("channel %q: version %d is not one the factory lists", c.ModuleName, v)
			}
		}
		for _, k := range c.Kinds {
			if !slices.Contains(declared.Kinds, k) {
				return fmt.Errorf("channel %q: kind %q is not one the factory lists", c.ModuleName, k)
			}
		}
		for _, prev := range t.Channels[:i] {
			if prev.ModuleName == c.ModuleName {
				return fmt.Errorf("duplicate channel %q", c.ModuleName)
			}
		}
	}
	all := opensOf(ActionTunnel)
	for i, o := range t.Opens {
		if !slices.Contains(all, o) {
			return fmt.Errorf("opens: %q is not one of %s", o, strings.Join(all, ", "))
		}
		if slices.Contains(t.Opens[:i], o) {
			return fmt.Errorf("opens: duplicate %q", o)
		}
	}
	return nil
}

// BuildFile is a file an operator uploaded for a file field. Build values hold
// its id; a factory.build request carries the file itself under files, with a
// link to download it from.
type BuildFile struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"` // lowercase hex
	MediaType string `json:"media_type,omitempty"`
	// URL is where the factory GETs the file: a link (IsLink), core's own
	// signed path valid until a minute past the build's deadline. Set in a
	// factory.build request only.
	URL string `json:"url,omitempty"`
}

// ValidateFile checks a file against a file field's accept and max_size. Core
// runs it when a file is used in a value; a factory may run it again on the
// files of a request.
func ValidateFile(f FieldSpec, file BuildFile) error {
	if f.MaxSize > 0 && file.Size > f.MaxSize {
		return fmt.Errorf("larger than %d bytes", f.MaxSize)
	}
	if len(f.Accept) == 0 {
		return nil
	}
	name := strings.ToLower(file.Name)
	media, _, _ := strings.Cut(strings.ToLower(file.MediaType), ";")
	media = strings.TrimSpace(media)
	for _, a := range f.Accept {
		a = strings.ToLower(a)
		switch {
		case strings.HasPrefix(a, "."):
			if strings.HasSuffix(name, a) {
				return nil
			}
		case strings.HasSuffix(a, "/*"):
			if media != "" && strings.HasPrefix(media, strings.TrimSuffix(a, "*")) {
				return nil
			}
		case media == a:
			return nil
		}
	}
	return fmt.Errorf("must be one of: %s", strings.Join(f.Accept, ", "))
}

// checkCommandParam checks a command's param: a field spec of a build
// schema, or a stream, which is a command's only: a name, no default, no
// rules of a file's.
func checkCommandParam(p FieldSpec) error {
	if p.Type != FieldStream {
		return checkFieldSpec(p, scopeBuild)
	}
	switch {
	case !keyPattern.MatchString(p.Key):
		return fmt.Errorf("key must match %s", keyPattern)
	case p.Default != nil:
		return fmt.Errorf("a stream has no default")
	case len(p.Accept) > 0 || p.MaxSize != 0 || len(p.Options) > 0 || p.Pattern != "" || p.Min != nil || p.Max != nil:
		return fmt.Errorf("a stream takes no rules")
	}
	return validateText(p.Label, p.Description)
}
