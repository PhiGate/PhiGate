package gateway

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/phigate/phigate/internal/types"
)

// toolCallAccumulator reassembles the tool calls a provider streams in
// fragments.
//
// The wire form is not one chunk per call. The first fragment for a call
// carries its index, id, type and function name; every later fragment carries
// the index and a slice of the arguments JSON, to be concatenated in arrival
// order. Index — not position in the chunk — is what identifies which call a
// fragment belongs to, because a model emitting two calls interleaves them.
//
// # Why the calls are released only at the end of the stream
//
// Arguments are hydrated, and a placeholder is not guaranteed to arrive whole:
// "<V1>" can be split across two fragments as "<V" and "1>", and hydrating
// either half yields nothing. Only the concatenated string is safe to hydrate,
// which is the same reason the text scanner holds a line until releasing it can
// no longer change the verdict.
//
// Nothing is lost by waiting. A tool call is not usable in parts — a client
// dispatches it once, whole, after finish_reason says to — so streaming the
// fragments through would buy latency no caller can spend.
type toolCallAccumulator struct {
	order []int // indices in first-seen order
	calls map[int]*types.ToolCall
	args  map[int]*strings.Builder
}

func newToolCallAccumulator() *toolCallAccumulator {
	return &toolCallAccumulator{
		calls: map[int]*types.ToolCall{},
		args:  map[int]*strings.Builder{},
	}
}

// add folds one streamed fragment into the call it belongs to.
func (a *toolCallAccumulator) add(frag types.ToolCall) {
	// A provider that omits index is sending one call at a time; treat those
	// fragments as belonging to call 0 rather than discarding them.
	idx := 0
	if frag.Index != nil {
		idx = *frag.Index
	}

	call, seen := a.calls[idx]
	if !seen {
		c := frag
		c.Index = nil // an index is a streaming artefact, not part of the call
		c.Function = nil
		a.calls[idx] = &c
		a.args[idx] = &strings.Builder{}
		a.order = append(a.order, idx)
		call = &c
	}

	// Later fragments fill in whatever the first one did not carry.
	if call.ID == "" {
		call.ID = frag.ID
	}
	if call.Type == "" {
		call.Type = frag.Type
	}
	for k, v := range frag.Extra {
		if call.Extra == nil {
			call.Extra = map[string]json.RawMessage{}
		}
		if _, exists := call.Extra[k]; !exists {
			call.Extra[k] = v
		}
	}

	if frag.Function == nil {
		return
	}
	if call.Function == nil {
		call.Function = &types.FunctionCall{}
	}
	if frag.Function.Name != "" {
		call.Function.Name = frag.Function.Name
	}
	for k, v := range frag.Function.Extra {
		if call.Function.Extra == nil {
			call.Function.Extra = map[string]json.RawMessage{}
		}
		if _, exists := call.Function.Extra[k]; !exists {
			call.Function.Extra[k] = v
		}
	}
	a.args[idx].WriteString(frag.Function.Arguments)
}

// assembled returns the reassembled calls, arguments still masked, in index
// order.
//
// Index order rather than arrival order: a client matches a call's result back
// by position, and the provider's own numbering is the authority on that.
func (a *toolCallAccumulator) assembled() []types.ToolCall {
	idx := append([]int(nil), a.order...)
	sort.Ints(idx)

	out := make([]types.ToolCall, 0, len(idx))
	for _, i := range idx {
		c := *a.calls[i]
		if c.Function != nil {
			fn := *c.Function
			fn.Arguments = a.args[i].String()
			c.Function = &fn
		}
		out = append(out, c)
	}
	return out
}
