package protocol

import (
	"fmt"
	"strings"
	"time"
)

func ValidateInbound(msg InboundMinionMessage) error {
	if err := validateMessage(
		msg.MessageID,
		msg.Type,
		msg.Version,
		msg.Timestamp,
		msg.ID,
		msg.EncryptedData,
		TypeInboundMinionMessage,
	); err != nil {
		return err
	}
	// Inbound carries the originating channel's source; outbound does not.
	return requireSource(msg.Source)
}

func ValidateOutbound(msg OutboundMinionMessage) error {
	return validateMessage(
		msg.MessageID,
		msg.Type,
		msg.Version,
		msg.Timestamp,
		msg.ID,
		msg.EncryptedData,
		TypeOutboundMinionMessage,
	)
}

func validateMessage(
	messageID string,
	msgType string,
	version string,
	timestamp string,
	id string,
	encryptedData string,
	expectedType string,
) error {
	if err := requireString("message_id", messageID); err != nil {
		return err
	}
	if err := requireString("type", msgType); err != nil {
		return err
	}
	if err := requireString("version", version); err != nil {
		return err
	}
	if err := requireString("timestamp", timestamp); err != nil {
		return err
	}
	if err := requireString("id", id); err != nil {
		return err
	}
	if err := requireString("encrypted_data", encryptedData); err != nil {
		return err
	}
	if msgType != expectedType {
		return newValidationError(ErrCodeInvalidType, fmt.Sprintf("type must be %q", expectedType))
	}
	if _, err := time.Parse(time.RFC3339, timestamp); err != nil {
		return newValidationError(ErrCodeInvalidTimestamp, "timestamp must be RFC3339")
	}
	return nil
}

func requireSource(source SourceInfo) error {
	if err := requireString("source.module", source.Module); err != nil {
		return err
	}
	if err := requireString("source.module_instance", source.ModuleInstance); err != nil {
		return err
	}
	if err := requireString("source.transport", source.Transport); err != nil {
		return err
	}
	if err := requireString("source.tenant", source.Tenant); err != nil {
		return err
	}
	return nil
}

func requireString(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return newValidationError(ErrCodeMissingField, fmt.Sprintf("%s is required", field))
	}
	return nil
}
