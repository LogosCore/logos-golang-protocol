package protocol

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func exampleFactoryCall(typ int) FactoryCall {
	c := FactoryCall{Type: typ, Request: 7, Build: bytes.Repeat([]byte{1}, 16), Deadline: 5000}
	switch typ {
	case FactoryInbound:
		c.ID, c.Data, c.Layers = bytes.Repeat([]byte{2}, 16), []byte("payload"), []int{CodecLayerSuite, CodecLayerEnvelope}
		c.Keys = [][]byte{[]byte("own"), []byte("replaced")}
	case FactoryOutbound:
		c.ID, c.Data, c.Layers = bytes.Repeat([]byte{2}, 16), []byte("message"), []int{CodecLayerSuite}
		c.Keys = [][]byte{[]byte("own")}
	case FactoryKeys:
		c.For, c.StageKey = FactoryKeysForStage, []byte("der")
	}
	return c
}

func TestFactoryCall(t *testing.T) {
	for _, typ := range []int{FactoryInbound, FactoryOutbound, FactoryKeys} {
		c := exampleFactoryCall(typ)
		b, err := EncodeFactoryCall(c)
		if err != nil {
			t.Fatalf("type %d: %v", typ, err)
		}
		back, err := DecodeFactoryCall(b)
		if err != nil || !reflect.DeepEqual(back, c) {
			t.Fatalf("type %d: %+v, %v", typ, back, err)
		}
	}
	for _, tc := range []struct {
		want string
		typ  int
		edit func(*FactoryCall)
	}{
		{"", FactoryInbound, func(c *FactoryCall) { c.Layers, c.Keys = []int{CodecLayerEnvelope}, nil }},
		{"", FactoryKeys, func(c *FactoryCall) { c.For, c.StageKey = FactoryKeysForBuild, nil }},
		{"request is 1 or more", FactoryInbound, func(c *FactoryCall) { c.Request = 0 }},
		{"the build is 16 bytes", FactoryKeys, func(c *FactoryCall) { c.Build = c.Build[:15] }},
		{"a deadline", FactoryOutbound, func(c *FactoryCall) { c.Deadline = 0 }},
		{"type 3", FactoryInbound, func(c *FactoryCall) { c.Type = FactoryAnswer }},
		{"the id is 16 bytes", FactoryInbound, func(c *FactoryCall) { c.ID = nil }},
		{"no bytes", FactoryOutbound, func(c *FactoryCall) { c.Data = nil }},
		{"layers are [1], [2] or [1, 2]", FactoryInbound, func(c *FactoryCall) { c.Layers = []int{2, 1} }},
		{"layers are", FactoryInbound, func(c *FactoryCall) { c.Layers = nil }},
		{"for and the stage key are a keys call's", FactoryInbound, func(c *FactoryCall) { c.For = 1 }},
		{"keys are the factory's suite's", FactoryOutbound, func(c *FactoryCall) { c.Layers = []int{CodecLayerEnvelope} }},
		{"1 to 5 keys", FactoryInbound, func(c *FactoryCall) { c.Keys = nil }},
		{"1 to 5 keys", FactoryInbound, func(c *FactoryCall) { c.Keys = make([][]byte, 6) }},
		{"the one key of the id", FactoryOutbound, func(c *FactoryCall) { c.Keys = append(c.Keys, []byte("x")) }},
		{"key 1 is 1 to 4096 bytes", FactoryInbound, func(c *FactoryCall) { c.Keys[1] = make([]byte, 4097) }},
		{"only request, build, deadline", FactoryKeys, func(c *FactoryCall) { c.Layers = []int{1} }},
		{"for is 1 (a build) or 2 (a stage)", FactoryKeys, func(c *FactoryCall) { c.For = 0 }},
		{"a stage key is a stage's", FactoryKeys, func(c *FactoryCall) { c.For = FactoryKeysForBuild }},
		{"a stage's key is 1 to 4096 bytes", FactoryKeys, func(c *FactoryCall) { c.StageKey = nil }},
	} {
		c := exampleFactoryCall(tc.typ)
		tc.edit(&c)
		err := c.Validate()
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("valid call refused: %v", err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("want %q, got %v", tc.want, err)
		}
	}
	if _, err := DecodeFactoryCall(make([]byte, MaxFactoryFrameSize+1)); err == nil {
		t.Error("a frame over the limit")
	}
}

func TestFactoryAnswer(t *testing.T) {
	one := uint64(1)
	five := uint64(5)
	inbound, outbound, keys := exampleFactoryCall(FactoryInbound), exampleFactoryCall(FactoryOutbound),
		exampleFactoryCall(FactoryKeys)
	answer := func(edit func(*FactoryAnswerFrame)) FactoryAnswerFrame {
		a := FactoryAnswerFrame{Type: FactoryAnswer, Request: 7}
		edit(&a)
		return a
	}
	ok := []struct {
		call FactoryCall
		a    FactoryAnswerFrame
	}{
		{inbound, answer(func(a *FactoryAnswerFrame) { a.Data, a.Opened = []byte{0xa0}, &one })},
		{outbound, answer(func(a *FactoryAnswerFrame) { a.Data = []byte("payload") })},
		{keys, answer(func(a *FactoryAnswerFrame) { a.Material, a.Wrapped = []byte("m"), []byte("w") })},
		{inbound, answer(func(a *FactoryAnswerFrame) { a.Failure = &CodecFailure{Kind: CodecFailNotOpened, Msg: "no key"} })},
		{keys, answer(func(a *FactoryAnswerFrame) { a.Failure = &CodecFailure{Kind: CodecFailRefused} })},
	}
	for i, tc := range ok {
		b, err := EncodeFactoryAnswer(tc.a)
		if err != nil {
			t.Fatalf("%d: %v", i, err)
		}
		back, err := DecodeFactoryAnswer(b)
		if err != nil || !reflect.DeepEqual(back, tc.a) || back.ValidateFor(tc.call) != nil {
			t.Fatalf("%d: %+v, %v, %v", i, back, err, back.ValidateFor(tc.call))
		}
	}
	envelopeOnly := inbound
	envelopeOnly.Layers, envelopeOnly.Keys = []int{CodecLayerEnvelope}, nil
	build := keys
	build.For, build.StageKey = FactoryKeysForBuild, nil
	for _, tc := range []struct {
		want string
		call FactoryCall
		a    FactoryAnswerFrame
	}{
		{"type 1", inbound, answer(func(a *FactoryAnswerFrame) { a.Type, a.Data = FactoryInbound, []byte{1} })},
		{"a result or a failure", inbound, answer(func(a *FactoryAnswerFrame) {})},
		{"a result or a failure", inbound, answer(func(a *FactoryAnswerFrame) {
			a.Data, a.Failure = []byte{1}, &CodecFailure{Kind: CodecFailOther}
		})},
		{"bytes or keys", keys, answer(func(a *FactoryAnswerFrame) { a.Data, a.Material = []byte{1}, []byte{1} })},
		{"failure kind 9", inbound, answer(func(a *FactoryAnswerFrame) { a.Failure = &CodecFailure{Kind: 9} })},
		{"the material is 1 to 4096", keys, answer(func(a *FactoryAnswerFrame) { a.Material = make([]byte, 4097) })},
		{"the wrapped material goes with the material", keys, answer(func(a *FactoryAnswerFrame) {
			a.Data, a.Wrapped = []byte{1}, []byte{1}
		})},
		{"request 8 answers 7", inbound, answer(func(a *FactoryAnswerFrame) { a.Request, a.Data, a.Opened = 8, []byte{1}, &one })},
		{"which key opened it", inbound, answer(func(a *FactoryAnswerFrame) { a.Data = []byte{1} })},
		{"opened 5 of 2 keys", inbound, answer(func(a *FactoryAnswerFrame) { a.Data, a.Opened = []byte{1}, &five })},
		{"opened is the factory's suite's", envelopeOnly, answer(func(a *FactoryAnswerFrame) {
			a.Data, a.Opened = []byte{1}, &one
		})},
		{"over 786432", envelopeOnly, answer(func(a *FactoryAnswerFrame) { a.Data = make([]byte, MaxMinionMessageSize+1) })},
		{"an inbound call's result is the message", inbound, answer(func(a *FactoryAnswerFrame) { a.Material = []byte{1} })},
		{"opened is an inbound call's", outbound, answer(func(a *FactoryAnswerFrame) { a.Data, a.Opened = []byte{1}, &one })},
		{"a keys call's result is the material", keys, answer(func(a *FactoryAnswerFrame) { a.Data = []byte{1} })},
		{"a stage's keys are wrapped", keys, answer(func(a *FactoryAnswerFrame) { a.Material = []byte{1} })},
		{"a build's keys are not wrapped", build, answer(func(a *FactoryAnswerFrame) {
			a.Material, a.Wrapped = []byte{1}, []byte{1}
		})},
	} {
		err := tc.a.ValidateFor(tc.call)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("want %q, got %v", tc.want, err)
		}
	}
	if CodecFailName(CodecFailNotMessage) != "not_message" || CodecFailName(9) != "failure 9" {
		t.Error("CodecFailName")
	}
}
