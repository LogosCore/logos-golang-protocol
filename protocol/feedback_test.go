package protocol

import (
	"bytes"
	"strings"
	"testing"
)

// Feedback travels as {0: 18, 1: id, 2: level, 3: msg, ...}; a level a later
// version adds reads as a warning.
func TestFeedback(t *testing.T) {
	in := FeedbackItem{T: ItemFeedback, ID: bytes.Repeat([]byte{7}, 8), Level: FeedbackError, Msg: "the disk is full",
		Code: "disk_full", Task: bytes.Repeat([]byte{1}, 16), At: 1_800_000_000, Count: 3}
	data, err := MarshalCBOR(in)
	if err != nil {
		t.Fatal(err)
	}
	var got FeedbackItem
	if err := UnmarshalCBOR(data, &got); err != nil || got.Validate() != nil || got.Msg != in.Msg || got.Count != 3 ||
		ItemType(data) != ItemFeedback || ItemName(ItemFeedback) != "feedback" {
		t.Fatalf("%+v %v", got, err)
	}
	if FeedbackLevelName(FeedbackError) != "error" || FeedbackLevelName(FeedbackWarning) != "warning" || FeedbackLevelName(9) != "warning" {
		t.Fatal("level names")
	}
	ok := FeedbackItem{ID: make([]byte, 8), Level: 9, Msg: "a later level"}
	if ok.Validate() != nil {
		t.Fatal("a later level refused")
	}
	for name, bad := range map[string]FeedbackItem{
		"id":       {ID: make([]byte, 4), Level: 1, Msg: "x"},
		"level":    {ID: make([]byte, 8), Msg: "x"},
		"no msg":   {ID: make([]byte, 8), Level: 1},
		"long msg": {ID: make([]byte, 8), Level: 1, Msg: strings.Repeat("x", MaxFeedbackMsg+1)},
		"not utf8": {ID: make([]byte, 8), Level: 1, Msg: "\xff"},
		"code":     {ID: make([]byte, 8), Level: 1, Msg: "x", Code: "Disk Full"},
		"task":     {ID: make([]byte, 8), Level: 1, Msg: "x", Task: []byte{1}},
	} {
		if bad.Validate() == nil {
			t.Errorf("%s passed", name)
		}
	}
}
