package gateway

import (
	"bytes"
	"encoding/json"

	"github.com/phigate/phigate/internal/compressor"
	"github.com/phigate/phigate/internal/redact"
	"github.com/phigate/phigate/internal/types"
)

// scanTools classifies every string in the request's `tools` definition and
// masks the description fields, returning the rewritten JSON.
//
// # Why the two are treated differently
//
// A tool definition is not uniform text. Its descriptions are prose written for
// the model, and masking them is safe — the system preamble already tells the
// model that <V1> is an anonymised placeholder. Everything else is contract:
// the function name, the property names, an enum's members. The client matches
// the model's call back against those exact strings, so masking one produces a
// call the client cannot dispatch and a tool the model cannot invoke correctly.
// Compressing the block wholesale would break tool calling outright, which is
// why only descriptions are rewritten.
//
// The rest is still scanned, because classification is a control in its own
// right. A description or a default value naming an internal host tells the
// egress policy something about this payload, and before this the policy saw
// none of it: `tools` sat in the passthrough map and was never read.
//
// Findings are noted on the same Session as everything else, so a credential
// pasted into a tool description raises MaxSensitivity and pins the request to
// the local backend rather than travelling to a cloud provider on every single
// request that carries this tool set.
func (g *Gateway) scanTools(view tenantView, req *types.ChatCompletionRequest, sess *compressor.Session) (json.RawMessage, error) {
	raw, ok := req.Extra["tools"]
	if !ok || len(raw) == 0 {
		return nil, nil
	}
	// UseNumber keeps numeric literals exactly as written. Decoding into `any`
	// otherwise turns every number into a float64, and a JSON Schema bound such
	// as "maximum": 9007199254740993 would come back out a different number
	// than the client sent.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var decoded any
	if err := dec.Decode(&decoded); err != nil {
		// A tools block PhiGate cannot parse is passed through as it arrived.
		// Refusing the request would break a client over a field the gateway
		// only inspects.
		return nil, nil
	}
	rewritten, err := g.walkTools(view, decoded, "", sess)
	if err != nil {
		return nil, err
	}
	out, err := json.Marshal(rewritten)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// walkTools recurses through the decoded definition. key is the object key the
// value was found under, which is what decides masking from classification;
// array elements inherit their array's key.
func (g *Gateway) walkTools(view tenantView, v any, key string, sess *compressor.Session) (any, error) {
	switch t := v.(type) {
	case string:
		if key == "description" {
			return view.masker.Process(t, sess)
		}
		g.classify(view, t, sess)
		return t, nil

	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			r, err := g.walkTools(view, e, key, sess)
			if err != nil {
				return nil, err
			}
			out[i] = r
		}
		return out, nil

	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			g.classify(view, k, sess)
			r, err := g.walkTools(view, e, k, sess)
			if err != nil {
				return nil, err
			}
			out[k] = r
		}
		return out, nil
	}
	// Numbers, booleans and null carry nothing to detect.
	return v, nil
}

// classify records what the detector finds in text without rewriting it.
//
// The identity replacement is deliberate: Redact both detects and substitutes,
// and here only the detection half is wanted. Nothing enters the dictionary, so
// no token is allocated for a value that is being left in place — a dictionary
// entry for a string that was never masked would hydrate other occurrences of
// it in the answer, which is not what the caller asked for.
func (g *Gateway) classify(view tenantView, text string, sess *compressor.Session) {
	if text == "" {
		return
	}
	_, findings := view.engine.Redact(text, func(f redact.Finding) string { return f.Text })
	for _, f := range findings {
		sess.Note(f)
	}
}
