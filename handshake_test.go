package trustmesh

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

type testClock struct{ t time.Time }

func (c *testClock) now() time.Time          { return c.t }
func (c *testClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// newPair builds two mutually trusting nodes sharing one test clock.
func newPair(t *testing.T) (*testClock, *Node, *Node) {
	t.Helper()
	clock := &testClock{t: time.Unix(1_700_000_000, 0)}
	pubA, privA := newKey(t)
	pubB, privB := newKey(t)
	a := NewNode("did:a", privA, map[DID]ed25519.PublicKey{"did:b": pubB}, WithClock(clock.now))
	b := NewNode("did:b", privB, map[DID]ed25519.PublicKey{"did:a": pubA}, WithClock(clock.now))
	return clock, a, b
}

func mustSession(t *testing.T, n *Node, id [SessionIDLen]byte) SessionInfo {
	t.Helper()
	info, ok := n.Session(id)
	if !ok {
		t.Fatalf("session %x not found", id[:4])
	}
	return info
}

func TestHandshakeHappyPath(t *testing.T) {
	_, a, b := newPair(t)

	invite, err := a.Initiate("did:b")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := b.Receive(invite)
	if err != nil || resp == nil {
		t.Fatalf("invite: resp=%v err=%v", resp, err)
	}
	confirm, err := a.Receive(resp)
	if err != nil || confirm == nil {
		t.Fatalf("response: confirm=%v err=%v", confirm, err)
	}
	out, err := b.Receive(confirm)
	if err != nil || out != nil {
		t.Fatalf("confirm: out=%v err=%v", out, err)
	}

	if got := mustSession(t, a, invite.SessionID).State; got != StateSucceeded {
		t.Fatalf("initiator state = %v", got)
	}
	if got := mustSession(t, b, invite.SessionID).State; got != StateSucceeded {
		t.Fatalf("responder state = %v", got)
	}
	if st := a.PeerStatus("did:b"); st.ConsecutiveFailures != 0 || st.Banned {
		t.Fatalf("unexpected peer status: %+v", st)
	}
}

func TestRetransmissionReplaysOriginalOutput(t *testing.T) {
	_, a, b := newPair(t)

	invite, _ := a.Initiate("did:b")
	resp1, _ := b.Receive(invite)
	resp2, _ := b.Receive(invite)
	if !messagesEqual(resp1, resp2) {
		t.Fatal("invite retransmission produced a different response")
	}
	if len(b.sessions) != 1 {
		t.Fatalf("invite retransmission created extra sessions: %d", len(b.sessions))
	}

	confirm1, _ := a.Receive(resp1)
	confirm2, _ := a.Receive(resp1)
	if !messagesEqual(confirm1, confirm2) {
		t.Fatal("response retransmission produced a different confirm")
	}

	if out, _ := b.Receive(confirm1); out != nil {
		t.Fatal("confirm should not produce output")
	}
	if out, _ := b.Receive(confirm1); out != nil {
		t.Fatal("confirm retransmission should not produce output")
	}

	// Invite retransmitted after completion still replays the original
	// response without disturbing the finished session.
	resp3, _ := b.Receive(invite)
	if !messagesEqual(resp1, resp3) {
		t.Fatal("post-completion invite retransmission changed the response")
	}
	if got := mustSession(t, b, invite.SessionID).State; got != StateSucceeded {
		t.Fatalf("responder state disturbed: %v", got)
	}
	if st := b.PeerStatus("did:a"); st.ConsecutiveFailures != 0 {
		t.Fatalf("retransmission settled extra failures: %+v", st)
	}
}

func TestCrossSessionProofFails(t *testing.T) {
	_, a, b := newPair(t)

	invite1, _ := a.Initiate("did:b")
	invite2, _ := a.Initiate("did:b")
	resp1, _ := b.Receive(invite1)
	if _, err := b.Receive(invite2); err != nil {
		t.Fatal(err)
	}

	// Replay session 1's response into session 2: binding mismatch.
	forged := *resp1
	forged.SessionID = invite2.SessionID
	if out, _ := a.Receive(&forged); out != nil {
		t.Fatal("cross-session proof produced output")
	}
	if got := mustSession(t, a, invite2.SessionID).State; got != StateFailed {
		t.Fatalf("session 2 state = %v, want failed", got)
	}
	if st := a.PeerStatus("did:b"); st.ConsecutiveFailures != 1 {
		t.Fatalf("failures = %d, want 1", st.ConsecutiveFailures)
	}

	// Session 1 is unaffected and completes; success resets the counter.
	confirm1, _ := a.Receive(resp1)
	if confirm1 == nil {
		t.Fatal("session 1 should still complete")
	}
	if got := mustSession(t, a, invite1.SessionID).State; got != StateSucceeded {
		t.Fatalf("session 1 state = %v", got)
	}
	if st := a.PeerStatus("did:b"); st.ConsecutiveFailures != 0 {
		t.Fatalf("success did not reset failures: %+v", st)
	}
}

func TestReflectionAndRoleConfusionFail(t *testing.T) {
	_, a, b := newPair(t)

	invite, _ := a.Initiate("did:b")

	// Reflecting the invite back to its sender must not open a session.
	if out, _ := a.Receive(invite); out != nil {
		t.Fatal("reflected invite produced output")
	}
	if len(a.sessions) != 1 || a.sessions[invite.SessionID].role != RoleInitiator {
		t.Fatal("reflected invite created a responder session")
	}

	resp, _ := b.Receive(invite)

	// Reflecting the response back to the responder is ignored.
	if out, _ := b.Receive(resp); out != nil {
		t.Fatal("reflected response produced output")
	}
	if got := mustSession(t, b, invite.SessionID).State; got != StatePending {
		t.Fatalf("reflected response disturbed session: %v", got)
	}

	// The responder's proof cannot be reused as the initiator's confirm.
	forged := &Message{
		Type:      MsgConfirm,
		SessionID: invite.SessionID,
		From:      "did:a",
		NonceA:    resp.NonceA,
		NonceB:    resp.NonceB,
		Proof:     resp.Proof,
	}
	if out, _ := b.Receive(forged); out != nil {
		t.Fatal("role-confused proof produced output")
	}
	if got := mustSession(t, b, invite.SessionID).State; got != StateFailed {
		t.Fatalf("session state = %v, want failed", got)
	}
	if st := b.PeerStatus("did:a"); st.ConsecutiveFailures != 1 {
		t.Fatalf("failures = %d, want 1", st.ConsecutiveFailures)
	}
}

func TestUnknownPeerRejected(t *testing.T) {
	_, a, b := newPair(t)
	if _, err := a.Initiate("did:stranger"); err != ErrUnknownPeer {
		t.Fatalf("err = %v", err)
	}
	if _, err := a.Initiate("did:a"); err != ErrSelfPeer {
		t.Fatalf("err = %v", err)
	}
	// An invite from an untrusted DID is ignored.
	pubC, _ := newKey(t)
	_ = pubC
	invite := &Message{Type: MsgInvite, SessionID: randSessionID(), From: "did:stranger", NonceA: randNonce()}
	if out, _ := b.Receive(invite); out != nil {
		t.Fatal("untrusted invite produced output")
	}
	if len(b.sessions) != 0 {
		t.Fatal("untrusted invite created a session")
	}
}

func TestFailedSessionStaysFailedOnRetransmission(t *testing.T) {
	_, a, b := newPair(t)

	invite, _ := a.Initiate("did:b")
	resp, _ := b.Receive(invite)

	// Corrupt the proof once: the session fails.
	bad := *resp
	bad.Proof = append([]byte(nil), resp.Proof...)
	bad.Proof[0] ^= 0xff
	if out, _ := a.Receive(&bad); out != nil {
		t.Fatal("bad proof produced output")
	}
	if got := mustSession(t, a, invite.SessionID).State; got != StateFailed {
		t.Fatalf("state = %v, want failed", got)
	}

	// The genuine response arriving late cannot revive the session and
	// must not settle anything again.
	if out, _ := a.Receive(resp); out != nil {
		t.Fatal("late valid response revived a failed session")
	}
	if got := mustSession(t, a, invite.SessionID).State; got != StateFailed {
		t.Fatalf("state = %v, want failed", got)
	}
	if st := a.PeerStatus("did:b"); st.ConsecutiveFailures != 1 {
		t.Fatalf("failures = %d, want exactly 1", st.ConsecutiveFailures)
	}
}
