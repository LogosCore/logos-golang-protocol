package protocol

const (
	TypeInboundAgentMessage  = "inbound.agent_message"
	TypeOutboundAgentMessage = "outbound.agent_message"
	VersionV1                = "1.0"
)

type SourceInfo struct {
	Module         string `json:"module"`
	ModuleInstance string `json:"module_instance"`
	Transport      string `json:"transport"`
	Tenant         string `json:"tenant"`
}

type MessageMeta map[string]any

type InboundAgentMessage struct {
	MessageID     string      `json:"message_id"`
	Type          string      `json:"type"`
	Version       string      `json:"version"`
	Timestamp     string      `json:"timestamp"`
	Source        SourceInfo  `json:"source"`
	ID            string      `json:"id"`
	EncryptedData string      `json:"encrypted_data"`
	Meta          MessageMeta `json:"meta,omitempty"`
}

type OutboundAgentMessage struct {
	MessageID     string      `json:"message_id"`
	Type          string      `json:"type"`
	Version       string      `json:"version"`
	Timestamp     string      `json:"timestamp"`
	Source        SourceInfo  `json:"source"`
	ID            string      `json:"id"`
	EncryptedData string      `json:"encrypted_data"`
	Meta          MessageMeta `json:"meta,omitempty"`
}
