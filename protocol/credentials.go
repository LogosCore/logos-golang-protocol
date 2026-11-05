package protocol

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// Credentials (docs: contracts/credentials.md): an operation's secrets as
// core records them, and as it gives one to a module that declared a field
// for it. A credential field (FieldCredential, FieldCredentialList) holds
// credential ids wherever core keeps a schema's values. What reaches the
// module is the credentials themselves: beside the values that name them
// (BuildRequest.Credentials, LinkFrame.Credentials), or in place of the ids
// in a task's args.

// Credential types: what kind of secret a credential is, and so which of
// Credential's fields it has (CredentialTypeFields).
const (
	// CredentialTypePlaintext is a password in the clear.
	CredentialTypePlaintext = "PLAINTEXT"
	// CredentialTypeKey is a private key, such as an SSH key.
	CredentialTypeKey = "KEY"
	// CredentialTypeCertificate is a client certificate, with its private
	// key or its PFX's password.
	CredentialTypeCertificate = "CERTIFICATE"
	// CredentialTypeTicket is a Kerberos ticket, as kirbi or ccache.
	CredentialTypeTicket = "TICKET"
	// CredentialTypeHash is a hash that opens something by itself, to pass
	// rather than crack.
	CredentialTypeHash = "HASH"
	// CredentialTypeHex is raw key material in hex, such as a Kerberos AES
	// key.
	CredentialTypeHex = "HEX"
	// CredentialTypeOther is anything else: a password and named keys.
	CredentialTypeOther = "OTHER"
)

// Credential fields, by the names Credential carries them under.
const (
	CredentialFieldUsername    = "username"
	CredentialFieldRealm       = "realm"
	CredentialFieldPassword    = "password"
	CredentialFieldKey         = "key"
	CredentialFieldPassphrase  = "passphrase"
	CredentialFieldCertificate = "certificate"
	CredentialFieldPrivateKey  = "private_key"
	CredentialFieldTicket      = "ticket"
	CredentialFieldService     = "service"
	CredentialFieldExpiresAt   = "expires_at"
	CredentialFieldHash        = "hash"
	CredentialFieldHex         = "hex"
	CredentialFieldAlgorithm   = "algorithm"
	CredentialFieldKeys        = "keys"
)

// Limits of credential values.
const (
	// MaxCredentialIDLength bounds a credential id (core's are UUIDs).
	MaxCredentialIDLength = 64
	// MaxCredentialListItems bounds a credential_list value, whatever its
	// max_items.
	MaxCredentialListItems = 16
	// MaxGivenCredentials bounds the credentials one request gives a module
	// (BuildRequest.Credentials, LinkFrame.Credentials).
	MaxGivenCredentials = 64
)

// CredentialFieldRule is one field of a credential type. Required is the
// value the type cannot do without; each type but OTHER has one.
type CredentialFieldRule struct {
	Field    string
	Required bool
}

func optional(field string) CredentialFieldRule { return CredentialFieldRule{Field: field} }
func required(field string) CredentialFieldRule {
	return CredentialFieldRule{Field: field, Required: true}
}

// credentialTypes is which fields each type has, in the order they are
// listed. Core holds its credentials to it, and labels them for people.
var credentialTypes = []struct {
	name   string
	fields []CredentialFieldRule
}{
	{CredentialTypePlaintext, []CredentialFieldRule{optional(CredentialFieldUsername), optional(CredentialFieldRealm),
		required(CredentialFieldPassword)}},
	{CredentialTypeKey, []CredentialFieldRule{optional(CredentialFieldUsername), required(CredentialFieldKey),
		optional(CredentialFieldPassphrase)}},
	{CredentialTypeCertificate, []CredentialFieldRule{optional(CredentialFieldUsername), optional(CredentialFieldRealm),
		required(CredentialFieldCertificate), optional(CredentialFieldPrivateKey), optional(CredentialFieldPassword)}},
	{CredentialTypeTicket, []CredentialFieldRule{optional(CredentialFieldUsername), optional(CredentialFieldRealm),
		required(CredentialFieldTicket), optional(CredentialFieldService), optional(CredentialFieldExpiresAt)}},
	{CredentialTypeHash, []CredentialFieldRule{optional(CredentialFieldUsername), optional(CredentialFieldRealm),
		required(CredentialFieldHash), optional(CredentialFieldAlgorithm)}},
	{CredentialTypeHex, []CredentialFieldRule{optional(CredentialFieldUsername), optional(CredentialFieldRealm),
		required(CredentialFieldHex), optional(CredentialFieldAlgorithm)}},
	{CredentialTypeOther, []CredentialFieldRule{optional(CredentialFieldUsername), optional(CredentialFieldPassword),
		optional(CredentialFieldKeys)}},
}

// credentialFieldNames is every field a Credential carries, in its order.
var credentialFieldNames = []string{
	CredentialFieldUsername, CredentialFieldRealm, CredentialFieldPassword, CredentialFieldKey,
	CredentialFieldPassphrase, CredentialFieldCertificate, CredentialFieldPrivateKey, CredentialFieldTicket,
	CredentialFieldService, CredentialFieldExpiresAt, CredentialFieldHash, CredentialFieldHex,
	CredentialFieldAlgorithm, CredentialFieldKeys,
}

// CredentialTypes lists the credential types, in the order they are offered.
func CredentialTypes() []string {
	out := make([]string, len(credentialTypes))
	for i, t := range credentialTypes {
		out[i] = t.name
	}
	return out
}

// IsCredentialType reports whether t is one of the credential types.
func IsCredentialType(t string) bool {
	_, ok := CredentialTypeFields(t)
	return ok
}

// CredentialTypeFields is type t's fields, in their order; false for a type
// that is not one.
func CredentialTypeFields(t string) ([]CredentialFieldRule, bool) {
	for _, ct := range credentialTypes {
		if ct.name == t {
			return slices.Clone(ct.fields), true
		}
	}
	return nil, false
}

// CredentialFieldNames is every field a credential can carry, in order.
func CredentialFieldNames() []string { return slices.Clone(credentialFieldNames) }

// Credential is a credential as core gives it to a module: its id and name,
// its type, and the fields of its type that hold a value. What else core
// keeps of it (properties, tags, validity, comments) is the operators' notes
// and stays with core.
type Credential struct {
	ID          string `json:"id"                    cbor:"1,keyasint"`
	Name        string `json:"name,omitempty"        cbor:"2,keyasint,omitempty"`
	Type        string `json:"type"                  cbor:"3,keyasint"`
	Username    string `json:"username,omitempty"    cbor:"4,keyasint,omitempty"`
	Realm       string `json:"realm,omitempty"       cbor:"5,keyasint,omitempty"`
	Password    string `json:"password,omitempty"    cbor:"6,keyasint,omitempty"`
	Key         string `json:"key,omitempty"         cbor:"7,keyasint,omitempty"`
	Passphrase  string `json:"passphrase,omitempty"  cbor:"8,keyasint,omitempty"`
	Certificate string `json:"certificate,omitempty" cbor:"9,keyasint,omitempty"`
	PrivateKey  string `json:"private_key,omitempty" cbor:"10,keyasint,omitempty"`
	Ticket      string `json:"ticket,omitempty"      cbor:"11,keyasint,omitempty"`
	Service     string `json:"service,omitempty"     cbor:"12,keyasint,omitempty"`
	// ExpiresAt is when a ticket expires, RFC 3339.
	ExpiresAt string `json:"expires_at,omitempty"  cbor:"13,keyasint,omitempty"`
	Hash      string `json:"hash,omitempty"        cbor:"14,keyasint,omitempty"`
	// Hex is hex digits, whole bytes, nothing between them.
	Hex       string `json:"hex,omitempty"         cbor:"15,keyasint,omitempty"`
	Algorithm string `json:"algorithm,omitempty"   cbor:"16,keyasint,omitempty"`
	// Keys are an OTHER's named keys.
	Keys []CredentialKey `json:"keys,omitempty"        cbor:"17,keyasint,omitempty"`
}

// CredentialKey is one of an OTHER credential's named keys.
type CredentialKey struct {
	Name    string `json:"name,omitempty" cbor:"1,keyasint,omitempty"`
	Content string `json:"content"        cbor:"2,keyasint"`
}

// Value is c's value in field (one of the CredentialField names): "" for
// keys, a list, and for a name that is not a field.
func (c Credential) Value(field string) string {
	switch field {
	case CredentialFieldUsername:
		return c.Username
	case CredentialFieldRealm:
		return c.Realm
	case CredentialFieldPassword:
		return c.Password
	case CredentialFieldKey:
		return c.Key
	case CredentialFieldPassphrase:
		return c.Passphrase
	case CredentialFieldCertificate:
		return c.Certificate
	case CredentialFieldPrivateKey:
		return c.PrivateKey
	case CredentialFieldTicket:
		return c.Ticket
	case CredentialFieldService:
		return c.Service
	case CredentialFieldExpiresAt:
		return c.ExpiresAt
	case CredentialFieldHash:
		return c.Hash
	case CredentialFieldHex:
		return c.Hex
	case CredentialFieldAlgorithm:
		return c.Algorithm
	}
	return ""
}

func (c Credential) has(field string) bool {
	if field == CredentialFieldKeys {
		return len(c.Keys) > 0
	}
	return c.Value(field) != ""
}

// Validate checks c as a module may trust it: an id, a type that is one, a
// value in each field its type requires and in none it has not, hex digits
// in whole bytes in hex, an RFC 3339 expiry.
func (c Credential) Validate() error {
	if c.ID == "" || len(c.ID) > MaxCredentialIDLength {
		return fmt.Errorf("credential: an id of 1..%d characters", MaxCredentialIDLength)
	}
	rules, ok := CredentialTypeFields(c.Type)
	if !ok {
		return fmt.Errorf("credential %s: type %q is not one of %s", c.ID, c.Type, strings.Join(CredentialTypes(), ", "))
	}
	var extra []string
	for _, f := range credentialFieldNames {
		if c.has(f) && !slices.ContainsFunc(rules, func(r CredentialFieldRule) bool { return r.Field == f }) {
			extra = append(extra, f)
		}
	}
	if len(extra) > 0 {
		return fmt.Errorf("credential %s: a %s has no %s", c.ID, c.Type, strings.Join(extra, ", "))
	}
	for _, r := range rules {
		if r.Required && !c.has(r.Field) {
			return fmt.Errorf("credential %s: a %s needs a %s", c.ID, c.Type, r.Field)
		}
	}
	if c.Hex != "" && !isHexBytes(c.Hex) {
		return fmt.Errorf("credential %s: hex is not hex digits in whole bytes", c.ID)
	}
	if c.ExpiresAt != "" {
		if _, err := time.Parse(time.RFC3339, c.ExpiresAt); err != nil {
			return fmt.Errorf("credential %s: expires_at is not an RFC 3339 time", c.ID)
		}
	}
	return nil
}

func isHexBytes(s string) bool {
	if len(s)%2 != 0 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

// isCredentialField reports whether f holds credential ids.
func isCredentialField(t FieldType) bool { return t == FieldCredential || t == FieldCredentialList }

// ValidateCredential checks a credential given for field f: valid in itself,
// and of a type f accepts (any, when f names none).
func ValidateCredential(f FieldSpec, c Credential) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if len(f.Accept) > 0 && !slices.Contains(f.Accept, c.Type) {
		return fmt.Errorf("credential %s is a %s; the field takes %s", c.ID, c.Type, strings.Join(f.Accept, ", "))
	}
	return nil
}

// FieldCredentialIDs is the credential ids the value of field f holds: one
// for a credential, the list for a credential_list. Nil for a field of
// another type, or a value that is not ids.
func FieldCredentialIDs(f FieldSpec, v any) []string {
	switch f.Type {
	case FieldCredential:
		if s, ok := v.(string); ok && s != "" {
			return []string{s}
		}
	case FieldCredentialList:
		ids, err := stringItems(v)
		if err == nil {
			return ids
		}
	}
	return nil
}

// CredentialIDs is every credential id the values of fields name, each once,
// in the fields' order: the credentials core gives a module beside them.
func CredentialIDs(fields []FieldSpec, values map[string]any) []string {
	var out []string
	for _, f := range fields {
		for _, id := range FieldCredentialIDs(f, values[f.Key]) {
			if !slices.Contains(out, id) {
				out = append(out, id)
			}
		}
	}
	return out
}

// FieldCredentials are the credentials the value of field f names, in its
// order, from those core gave beside the values (BuildRequest.Credentials,
// LinkFrame.Credentials), each checked against f (ValidateCredential). An id
// core gave none for is an error: the request is not whole.
func FieldCredentials(f FieldSpec, v any, given map[string]Credential) ([]Credential, error) {
	ids := FieldCredentialIDs(f, v)
	out := make([]Credential, 0, len(ids))
	for _, id := range ids {
		c, ok := given[id]
		if !ok {
			return nil, fmt.Errorf("%s: credential %s was not given with the values", f.Key, id)
		}
		if err := ValidateCredential(f, c); err != nil {
			return nil, fmt.Errorf("%s: %w", f.Key, err)
		}
		out = append(out, c)
	}
	return out, nil
}

// validateGivenCredentials checks the credentials a request gives: each
// valid and under its own id, MaxGivenCredentials at most.
func validateGivenCredentials(given map[string]Credential) error {
	if len(given) > MaxGivenCredentials {
		return fmt.Errorf("%d credentials, %d at most", len(given), MaxGivenCredentials)
	}
	for id, c := range given {
		if c.ID != id {
			return fmt.Errorf("credential %s given under %q", c.ID, id)
		}
		if err := c.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// ArgCredential reads a credential param's arg in a task: the credential,
// in place of the id core keeps.
func ArgCredential[K comparable](args map[K]any, key K) (*Credential, error) {
	raw, err := argRaw(args, key)
	if err != nil || raw == nil {
		return nil, err
	}
	var c Credential
	if err := cborDec.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("a credential arg: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// ArgCredentials reads a credential_list param's arg in a task: the
// credentials, in the operator's order.
func ArgCredentials[K comparable](args map[K]any, key K) ([]Credential, error) {
	raw, err := argRaw(args, key)
	if err != nil || raw == nil {
		return nil, err
	}
	var list []Credential
	if err := cborDec.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("a credential list arg: %w", err)
	}
	if len(list) > MaxCredentialListItems {
		return nil, fmt.Errorf("a credential list arg of %d, %d at most", len(list), MaxCredentialListItems)
	}
	for _, c := range list {
		if err := c.Validate(); err != nil {
			return nil, err
		}
	}
	return list, nil
}

// argRaw is an arg as the CBOR it came as: kept so by Args for an
// integer-keyed map or a list of them, encoded again for anything else (an
// arg made in process). Nil, without an error, when the arg is not there.
func argRaw[K comparable](args map[K]any, key K) (cbor.RawMessage, error) {
	v, ok := args[key]
	if !ok || v == nil {
		return nil, nil
	}
	if raw, ok := v.(cbor.RawMessage); ok {
		return raw, nil
	}
	b, err := cborEnc.Marshal(v)
	if err != nil {
		return nil, errors.New("an arg that does not encode")
	}
	return b, nil
}
