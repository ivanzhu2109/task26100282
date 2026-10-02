package trustmesh

import (
	"bytes"
	"crypto/rand"
	"time"
)

// Initiate starts a new handshake with a peer and returns the invite message
// the caller must deliver.
func (n *Node) Initiate(peer DID) (*Message, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	now := n.now()
	n.sweep(now)
	if peer == n.self {
		return nil, ErrSelfPeer
	}
	if _, ok := n.trusted[peer]; !ok {
		return nil, ErrUnknownPeer
	}
	if n.banned(peer) {
		return nil, ErrPeerBanned
	}
	s := &session{
		id:       randSessionID(),
		peer:     peer,
		role:     RoleInitiator,
		state:    StatePending,
		nonceA:   randNonce(),
		deadline: now.Add(authTimeout),
	}
	invite := &Message{Type: MsgInvite, SessionID: s.id, From: n.self, NonceA: s.nonceA}
	n.sessions[s.id] = s
	return invite, nil
}

// Receive processes an inbound message and returns the message to send back,
// or nil if no reply is needed.
func (n *Node) Receive(msg *Message) (*Message, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	now := n.now()
	n.sweep(now)
	if msg == nil {
		return nil, nil
	}
	if n.banned(msg.From) {
		return nil, nil
	}
	if msg.Type == MsgInvite {
		return n.receiveInvite(msg, now), nil
	}
	s, ok := n.sessions[msg.SessionID]
	if !ok {
		return nil, nil
	}
	switch msg.Type {
	case MsgResponse:
		return n.receiveResponse(s, msg, now), nil
	case MsgConfirm:
		return n.receiveConfirm(s, msg, now), nil
	}
	return nil, nil
}

// receiveInvite handles step 1 on the responder side.
func (n *Node) receiveInvite(msg *Message, now time.Time) *Message {
	if msg.From == n.self {
		return nil
	}
	if _, ok := n.trusted[msg.From]; !ok {
		return nil
	}
	if s, ok := n.sessions[msg.SessionID]; ok {
		// An identical retransmission of the accepted invite replays the
		// original response; anything else is ignored.
		if s.role == RoleResponder && replayable(s) && s.invite != nil && messagesEqual(s.invite, msg) {
			return cloneMessage(s.response)
		}
		return nil
	}
	s := &session{
		id:       msg.SessionID,
		peer:     msg.From,
		role:     RoleResponder,
		state:    StatePending,
		nonceA:   msg.NonceA,
		nonceB:   randNonce(),
		deadline: now.Add(authTimeout),
	}
	proof := signProof(n.priv, RoleResponder, s.peer, n.self, s.id, s.nonceA, s.nonceB)
	out := &Message{
		Type:      MsgResponse,
		SessionID: s.id,
		From:      n.self,
		NonceA:    s.nonceA,
		NonceB:    s.nonceB,
		Proof:     proof,
	}
	s.invite = cloneMessage(msg)
	s.response = cloneMessage(out)
	n.sessions[s.id] = s
	return out
}

// receiveResponse handles step 2 on the initiator side.
func (n *Node) receiveResponse(s *session, msg *Message, now time.Time) *Message {
	if s.role != RoleInitiator {
		return nil
	}
	if s.response != nil && replayable(s) && messagesEqual(s.response, msg) {
		return cloneMessage(s.confirm)
	}
	if s.state != StatePending {
		return nil
	}
	if !n.validResponse(s, msg) {
		s.state = StateFailed
		n.recordFailure(s.peer, now)
		return nil
	}
	s.nonceB = msg.NonceB
	proof := signProof(n.priv, RoleInitiator, n.self, s.peer, s.id, s.nonceA, s.nonceB)
	out := &Message{
		Type:      MsgConfirm,
		SessionID: s.id,
		From:      n.self,
		NonceA:    s.nonceA,
		NonceB:    s.nonceB,
		Proof:     proof,
	}
	s.state = StateSucceeded
	n.recordSuccess(s.peer)
	s.response = cloneMessage(msg)
	s.confirm = cloneMessage(out)
	return out
}

// receiveConfirm handles step 3 on the responder side.
func (n *Node) receiveConfirm(s *session, msg *Message, now time.Time) *Message {
	if s.role != RoleResponder {
		return nil
	}
	if s.confirm != nil && replayable(s) && messagesEqual(s.confirm, msg) {
		return nil
	}
	if s.state != StatePending {
		return nil
	}
	if !n.validConfirm(s, msg) {
		s.state = StateFailed
		n.recordFailure(s.peer, now)
		return nil
	}
	s.state = StateSucceeded
	n.recordSuccess(s.peer)
	s.confirm = cloneMessage(msg)
	return nil
}

// validResponse checks binding fields and the responder's proof.
func (n *Node) validResponse(s *session, msg *Message) bool {
	if msg.From != s.peer || msg.NonceA != s.nonceA {
		return false
	}
	pub, ok := n.trusted[s.peer]
	if !ok {
		return false
	}
	return verifyProof(pub, RoleResponder, n.self, s.peer, s.id, s.nonceA, msg.NonceB, msg.Proof)
}

// validConfirm checks binding fields and the initiator's proof.
func (n *Node) validConfirm(s *session, msg *Message) bool {
	if msg.From != s.peer || msg.NonceA != s.nonceA || msg.NonceB != s.nonceB {
		return false
	}
	pub, ok := n.trusted[s.peer]
	if !ok {
		return false
	}
	return verifyProof(pub, RoleInitiator, s.peer, n.self, s.id, s.nonceA, s.nonceB, msg.Proof)
}

// replayable reports whether a session may answer an identical retransmission
// with its original output. Failed, cancelled and expired sessions never do.
func replayable(s *session) bool {
	return s.state == StatePending || s.state == StateSucceeded
}

func messagesEqual(a, b *Message) bool {
	return a.Type == b.Type &&
		a.SessionID == b.SessionID &&
		a.From == b.From &&
		a.NonceA == b.NonceA &&
		a.NonceB == b.NonceB &&
		bytes.Equal(a.Proof, b.Proof)
}

func cloneMessage(m *Message) *Message {
	if m == nil {
		return nil
	}
	c := *m
	c.Proof = bytes.Clone(m.Proof)
	return &c
}

func randSessionID() [SessionIDLen]byte {
	var b [SessionIDLen]byte
	mustRand(b[:])
	return b
}

func randNonce() [NonceLen]byte {
	var b [NonceLen]byte
	mustRand(b[:])
	return b
}

func mustRand(b []byte) {
	if _, err := rand.Read(b); err != nil {
		panic("trustmesh: crypto/rand unavailable: " + err.Error())
	}
}
