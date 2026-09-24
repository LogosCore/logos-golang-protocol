package protocol

const (
	TypeInboundMinionMessage  = "inbound.minion_message"
	TypeOutboundMinionMessage = "outbound.minion_message"
	VersionV1                 = "1.0"
)

type SourceInfo struct {
	Module         string `json:"module"`
	ModuleInstance string `json:"module_instance"`
	Transport      string `json:"transport"`
	Tenant         string `json:"tenant"`
}

type MessageMeta map[string]any

type InboundMinionMessage struct {
	MessageID     string      `json:"message_id"`
	Type          string      `json:"type"`
	Version       string      `json:"version"`
	Timestamp     string      `json:"timestamp"`
	Source        SourceInfo  `json:"source"`
	ID            string      `json:"id"`
	EncryptedData string      `json:"encrypted_data"`
	Meta          MessageMeta `json:"meta,omitempty"`
}

// OutboundMinionMessage is the core-to-channel response. Per the data-plane
// contract it exposes only id + encrypted_data plus envelope metadata, and
// deliberately carries no source: it is core's reply for an existing id.
type OutboundMinionMessage struct {
	MessageID     string      `json:"message_id"`
	Type          string      `json:"type"`
	Version       string      `json:"version"`
	Timestamp     string      `json:"timestamp"`
	ID            string      `json:"id"`
	EncryptedData string      `json:"encrypted_data"`
	Meta          MessageMeta `json:"meta,omitempty"`
}
