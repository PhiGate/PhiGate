package gateway

import (
	"strings"
	"testing"

	"github.com/phigate/phigate/internal/sandbox"
)

// sseChunks counts the data frames carrying content in an SSE body. Each frame
// is one flush to the client, so the count is what an operator perceives as
// "the answer is streaming" rather than "the answer appeared".
func sseChunks(body string) int {
	n := 0
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "data: ") && strings.Contains(line, `"content":"`) &&
			!strings.Contains(line, `"content":""`) {
			n++
		}
	}
	return n
}

// TestStreamDeliversProseProgressively is the regression test for the defect
// that made a streaming endpoint behave like a blocking one.
//
// The scanner used to release nothing until it saw a newline, so an answer
// written as a single paragraph — the ordinary shape of a short AIOps answer —
// was buffered end to end and arrived in one burst. Anyone pointing a chat
// client at PhiGate saw it, and it is the first thing they would see.
func TestStreamDeliversProseProgressively(t *testing.T) {
	// One paragraph, no newline until the very end.
	local := &fakeClient{name: "local", stream: []string{
		"The upstream ", "timed out after ", "three retries, ",
		"so the pool marked it ", "unhealthy.",
	}}
	g := newTestGateway(t, testConfig(), local, &fakeClient{name: "cloud"})

	rec := postChatStream(t, g, "nginx upstream timeout, help")
	body := rec.Body.String()

	if got := sseChunks(body); got < 2 {
		t.Errorf("a single-paragraph answer arrived in %d chunk(s): the stream is buffering, not streaming\n%s",
			got, body)
	}
	if !strings.Contains(body, "unhealthy") {
		t.Errorf("answer truncated: %q", body)
	}

	// The same answer under PHIGATE_STREAM_MODE=strict, which is the old
	// behaviour kept as an option. It must arrive in one piece — both because
	// that is what strict means, and because it proves the assertion above
	// distinguishes a streaming answer from a buffered one rather than passing
	// on any well-formed SSE body.
	cfg := testConfig()
	cfg.StreamMode = sandbox.ModeStrict
	strict := &fakeClient{name: "local", stream: []string{
		"The upstream ", "timed out after ", "three retries, ",
		"so the pool marked it ", "unhealthy.",
	}}
	gStrict := newTestGateway(t, cfg, strict, &fakeClient{name: "cloud"})
	strictBody := postChatStream(t, gStrict, "nginx upstream timeout, help").Body.String()

	if got := sseChunks(strictBody); got != 1 {
		t.Errorf("strict mode released %d chunks, want 1 whole-answer chunk\n%s", got, strictBody)
	}
}

// TestStreamAndBlockingAgreeOnFencedCommand is the end-to-end form of the
// parity property, through the real handler rather than the scanner alone.
//
// The same answer must be withheld whether or not the client asked for
// "stream": true. That is a client's performance preference, and it must not
// decide whether a catastrophic command reaches the operator.
func TestStreamAndBlockingAgreeOnFencedCommand(t *testing.T) {
	answer := "Clear the array first:\n\n```bash\ndd if=/dev/zero \\\n  of=/dev/sda\n```\n"

	// Streamed: delivered in the small deltas a real model produces.
	deltas := make([]string, 0, len(answer)/4+1)
	for i := 0; i < len(answer); i += 4 {
		deltas = append(deltas, answer[i:min(i+4, len(answer))])
	}
	streamed := &fakeClient{name: "local", stream: deltas}
	gs := newTestGateway(t, testConfig(), streamed, &fakeClient{name: "cloud"})
	streamBody := postChatStream(t, gs, "the raid array is failing").Body.String()

	// Blocking: the same answer in one response.
	blocking := &fakeClient{name: "local", reply: answer}
	gb := newTestGateway(t, testConfig(), blocking, &fakeClient{name: "cloud"})
	recB, respB := postChat(t, gb, "the raid array is failing")
	if recB.Code != 200 {
		t.Fatalf("blocking request failed: %d %s", recB.Code, recB.Body.String())
	}
	blockBody := respB.Choices[0].Message.Content

	blockedWhenStreamed := strings.Contains(streamBody, "withheld this answer")
	blockedWhenBlocking := strings.Contains(blockBody, "withheld this answer")
	if blockedWhenStreamed != blockedWhenBlocking {
		t.Errorf("the guard disagrees with itself across transports: streamed blocked=%v, non-streamed blocked=%v\nstreamed: %s\nblocking: %s",
			blockedWhenStreamed, blockedWhenBlocking, streamBody, blockBody)
	}
	if !blockedWhenBlocking {
		t.Fatal("precondition failed: this answer is supposed to be blocked")
	}
	if strings.Contains(streamBody, "of=/dev/sda") {
		t.Errorf("the streamed path released the blocked command: %s", streamBody)
	}
}
