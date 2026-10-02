package trustmesh

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func TestSuccessJustBeforeDeadline(t *testing.T) {
	clock, a, b := newPair(t)
	invite, _ := a.Initiate("did:b")
	resp, _ := b.Receive(invite)

	clock.advance(authTimeout - time.Nanosecond)
	confirm, _ := a.Receive(resp)
	if confirm == nil {
		t.Fatal("auth completing strictly before 10s must succeed")
	}
	if got := mustSession(t, a, invite.SessionID).State; got != StateSucceeded {
		t.Fatalf("state = %v", got)
	}
}

func TestTimeoutAtExactDeadline(t *testing.T) {
	clock, a, b := newPair(t)
	invite, _ := a.Initiate("did:b")
	resp, _ := b.Receive(invite)

	// Exactly 10 seconds: already timed out.
	clock.advance(authTimeout)
	if out, _ := a.Receive(resp); out != nil {
		t.Fatal("response at exactly 10s must not succeed")
	}
	if got := mustSession(t, a, invite.SessionID).State; got != StateExpired {
		t.Fatalf("state = %v, want expired", got)
	}
	if st := a.PeerStatus("did:b"); st.ConsecutiveFailures != 1 {
		t.Fatalf("failures = %d, want 1", st.ConsecutiveFailures)
	}
}

func TestResponderTimeoutRejectsLateConfirm(t *testing.T) {
	clock, a, b := newPair(t)
	invite, _ := a.Initiate("did:b")
	resp, _ := b.Receive(invite)
	confirm, _ := a.Receive(resp) // initiator succeeds locally in time

	clock.advance(authTimeout)
	if out, _ := b.Receive(confirm); out != nil {
		t.Fatal("late confirm produced output")
	}
	if got := mustSession(t, b, invite.SessionID).State; got != StateExpired {
		t.Fatalf("state = %v, want expired", got)
	}
	if st := b.PeerStatus("did:a"); st.ConsecutiveFailures != 1 {
		t.Fatalf("failures = %d, want 1", st.ConsecutiveFailures)
	}
	// The initiator's local success stands regardless.
	if got := mustSession(t, a, invite.SessionID).State; got != StateSucceeded {
		t.Fatalf("initiator state = %v, want succeeded", got)
	}
}

func TestBanAfterFiveConsecutiveFailures(t *testing.T) {
	clock, a, b := newPair(t)

	var extra [SessionIDLen]byte
	for i := 0; i < banThreshold; i++ {
		if _, err := a.Initiate("did:b"); err != nil {
			t.Fatal(err)
		}
	}
	// One more session with a later deadline that the ban must cancel.
	clock.advance(authTimeout / 2)
	m, _ := a.Initiate("did:b")
	extra = m.SessionID

	clock.advance(authTimeout / 2)
	st := a.PeerStatus("did:b")
	if !st.Banned {
		t.Fatal("peer not banned after 5 consecutive failures")
	}
	if want := clock.now().Add(banDuration); !st.BanUntil.Equal(want) {
		t.Fatalf("banUntil = %v, want %v", st.BanUntil, want)
	}
	if got := mustSession(t, a, extra).State; got != StateCancelled {
		t.Fatalf("pending session state = %v, want cancelled", got)
	}
	if st.ConsecutiveFailures != banThreshold {
		t.Fatalf("failures = %d, want %d (cancel must not add)", st.ConsecutiveFailures, banThreshold)
	}

	// During the ban: no new initiation, inbound traffic dropped.
	if _, err := a.Initiate("did:b"); err != ErrPeerBanned {
		t.Fatalf("initiate during ban: err = %v", err)
	}
	bInvite, err := b.Initiate("did:a")
	if err != nil {
		t.Fatal(err)
	}
	before := len(a.sessions)
	if out, _ := a.Receive(bInvite); out != nil {
		t.Fatal("banned peer's invite produced output")
	}
	if len(a.sessions) != before {
		t.Fatal("banned peer's invite created a session")
	}

	// Ban does not extend and does not release early.
	clock.advance(banDuration - time.Second)
	if st := a.PeerStatus("did:b"); !st.Banned {
		t.Fatal("ban lifted before its deadline")
	}

	// At the deadline the ban expires and the counter resets.
	clock.advance(time.Second)
	st = a.PeerStatus("did:b")
	if st.Banned || st.ConsecutiveFailures != 0 {
		t.Fatalf("after ban expiry: %+v", st)
	}
	if _, err := a.Initiate("did:b"); err != nil {
		t.Fatalf("initiate after ban expiry: %v", err)
	}
	// Old cancelled sessions never come back.
	if got := mustSession(t, a, extra).State; got != StateCancelled {
		t.Fatalf("old session state = %v, want cancelled", got)
	}
}

func TestBanDoesNotAffectOtherPeers(t *testing.T) {
	clock, a, _ := newPair(t)
	pubC, privC := newKey(t)
	a.trusted["did:c"] = pubC
	c := NewNode("did:c", privC, map[DID]ed25519.PublicKey{"did:a": a.priv.Public().(ed25519.PublicKey)}, WithClock(clock.now))

	for i := 0; i < banThreshold; i++ {
		a.Initiate("did:b")
	}
	clock.advance(authTimeout)
	if st := a.PeerStatus("did:b"); !st.Banned {
		t.Fatal("b should be banned")
	}

	invite, err := a.Initiate("did:c")
	if err != nil {
		t.Fatalf("peer c unaffected: %v", err)
	}
	resp, _ := c.Receive(invite)
	confirm, _ := a.Receive(resp)
	c.Receive(confirm)
	if got := mustSession(t, c, invite.SessionID).State; got != StateSucceeded {
		t.Fatalf("peer c handshake state = %v", got)
	}
}

func TestSuccessResetsConsecutiveFailures(t *testing.T) {
	_, a, b := newPair(t)

	// Two failures via corrupted proofs.
	for i := 0; i < 2; i++ {
		invite, _ := a.Initiate("did:b")
		resp, _ := b.Receive(invite)
		bad := *resp
		bad.Proof = append([]byte(nil), resp.Proof...)
		bad.Proof[0] ^= 0xff
		a.Receive(&bad)
	}
	if st := a.PeerStatus("did:b"); st.ConsecutiveFailures != 2 {
		t.Fatalf("failures = %d, want 2", st.ConsecutiveFailures)
	}

	invite, _ := a.Initiate("did:b")
	resp, _ := b.Receive(invite)
	if confirm, _ := a.Receive(resp); confirm == nil {
		t.Fatal("handshake should succeed")
	}
	if st := a.PeerStatus("did:b"); st.ConsecutiveFailures != 0 {
		t.Fatalf("success did not reset counter: %+v", st)
	}
}

func TestSameInstantTimeoutsSettleInSessionIDOrder(t *testing.T) {
	clock, a, _ := newPair(t)

	// Inject six pending sessions sharing one deadline. Settlement must
	// process them in session-id byte order: the first five count as
	// failures and trigger the ban, the sixth is cancelled by it.
	deadline := clock.now().Add(authTimeout)
	var ids [][SessionIDLen]byte
	for i := 0; i < banThreshold+1; i++ {
		var id [SessionIDLen]byte
		id[SessionIDLen-1] = byte(i)
		a.sessions[id] = &session{
			id:       id,
			peer:     "did:b",
			role:     RoleInitiator,
			state:    StatePending,
			deadline: deadline,
		}
		ids = append(ids, id)
	}

	clock.advance(authTimeout)
	st := a.PeerStatus("did:b")
	if !st.Banned || st.ConsecutiveFailures != banThreshold {
		t.Fatalf("status = %+v, want banned with %d failures", st, banThreshold)
	}
	for i, id := range ids {
		got := a.sessions[id].state
		want := StateExpired
		if i == banThreshold {
			want = StateCancelled
		}
		if got != want {
			t.Fatalf("session %d state = %v, want %v", i, got, want)
		}
	}
}

func TestLongIdleSettlesAtOriginalDeadlines(t *testing.T) {
	clock, a, b := newPair(t)

	// Five unanswered initiations at T; their deadlines are all T+10s.
	for i := 0; i < banThreshold; i++ {
		if _, err := a.Initiate("did:b"); err != nil {
			t.Fatal(err)
		}
	}
	start := clock.now()

	// No calls for two hours. The ban ran T+10s .. T+10s+30min and is long
	// over; discovery now must not restart it.
	clock.advance(2 * time.Hour)
	st := a.PeerStatus("did:b")
	if st.Banned {
		t.Fatalf("ban must have expired at %v, still banned until %v", start.Add(authTimeout+banDuration), st.BanUntil)
	}
	if st.ConsecutiveFailures != 0 {
		t.Fatalf("counter must reset at ban expiry, got %d", st.ConsecutiveFailures)
	}
	for id, s := range a.sessions {
		if s.state != StateExpired {
			t.Fatalf("session %x state = %v, want expired", id[:4], s.state)
		}
	}

	// A fresh handshake works immediately after the long idle period.
	invite, err := a.Initiate("did:b")
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := b.Receive(invite)
	confirm, _ := a.Receive(resp)
	if confirm == nil {
		t.Fatal("handshake after idle should succeed")
	}
	b.Receive(confirm)
	if mustSession(t, b, invite.SessionID).State != StateSucceeded {
		t.Fatal("responder should succeed after idle")
	}
}

func TestLateProofCannotReviveExpiredSession(t *testing.T) {
	clock, a, b := newPair(t)

	invite, _ := a.Initiate("did:b")
	resp, _ := b.Receive(invite)
	confirm, _ := a.Receive(resp) // initiator succeeds at T
	if confirm == nil {
		t.Fatal("initiator should succeed in time")
	}

	// The confirm is delivered two hours late; the responder session
	// expired at T+10s and the failure settled then.
	clock.advance(2 * time.Hour)
	if out, _ := b.Receive(confirm); out != nil {
		t.Fatal("late confirm produced output")
	}
	info := mustSession(t, b, invite.SessionID)
	if info.State != StateExpired {
		t.Fatalf("state = %v, want expired", info.State)
	}
	if st := b.PeerStatus("did:a"); st.ConsecutiveFailures != 1 || st.Banned {
		t.Fatalf("late confirm changed settlement: %+v", st)
	}
}
