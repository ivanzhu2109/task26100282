package trustmesh

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"sort"
	"sync"
	"time"
)

var (
	ErrUnknownPeer = errors.New("trustmesh: peer not in trusted set")
	ErrPeerBanned  = errors.New("trustmesh: peer is banned")
	ErrSelfPeer    = errors.New("trustmesh: cannot challenge self")
)

// session is the mutable per-handshake state.
type session struct {
	id       [SessionIDLen]byte
	peer     DID
	role     Role
	state    SessionState
	nonceA   [NonceLen]byte
	nonceB   [NonceLen]byte
	deadline time.Time
	invite   *Message
	response *Message
	confirm  *Message
}

// peerState tracks consecutive failures and ban status for one peer.
type peerState struct {
	consecutiveFailures int
	banned              bool
	banUntil            time.Time
}

// Node is a TrustMesh institution node. All state lives in process memory.
// It is safe for concurrent use.
type Node struct {
	mu       sync.Mutex
	self     DID
	priv     ed25519.PrivateKey
	trusted  map[DID]ed25519.PublicKey
	now      func() time.Time
	sessions map[[SessionIDLen]byte]*session
	peers    map[DID]*peerState
}

// Option customizes a Node.
type Option func(*Node)

// WithClock overrides the time source (used for tests). The clock must be
// monotonic for correct timeout behaviour.
func WithClock(clock func() time.Time) Option {
	return func(n *Node) { n.now = clock }
}

// NewNode creates a node with its Ed25519 private key and the fixed trusted
// DID-to-public-key mapping.
func NewNode(self DID, priv ed25519.PrivateKey, trusted map[DID]ed25519.PublicKey, opts ...Option) *Node {
	n := &Node{
		self:     self,
		priv:     priv,
		trusted:  trusted,
		now:      time.Now,
		sessions: make(map[[SessionIDLen]byte]*session),
		peers:    make(map[DID]*peerState),
	}
	for _, opt := range opts {
		opt(n)
	}
	return n
}

// peerRecord returns the mutable record for a peer, creating it if needed.
func (n *Node) peerRecord(peer DID) *peerState {
	ps, ok := n.peers[peer]
	if !ok {
		ps = &peerState{}
		n.peers[peer] = ps
	}
	return ps
}

// sweep settles every event whose deadline has passed, using each event's own
// deadline as its effective time. It must run before any public operation.
func (n *Node) sweep(now time.Time) {
	var expired []*session
	for _, s := range n.sessions {
		if s.state == StatePending && !now.Before(s.deadline) {
			expired = append(expired, s)
		}
	}
	// Same-instant timeouts settle in session-id byte order.
	sort.Slice(expired, func(i, j int) bool {
		if !expired[i].deadline.Equal(expired[j].deadline) {
			return expired[i].deadline.Before(expired[j].deadline)
		}
		return bytes.Compare(expired[i].id[:], expired[j].id[:]) < 0
	})
	for _, s := range expired {
		if s.state != StatePending {
			// Already cancelled by a ban triggered earlier in this sweep.
			continue
		}
		s.state = StateExpired
		n.recordFailure(s.peer, s.deadline)
	}
	for did, ps := range n.peers {
		if ps.banned && !now.Before(ps.banUntil) {
			ps.banned = false
			ps.banUntil = time.Time{}
			ps.consecutiveFailures = 0
			if ps.consecutiveFailures == 0 && !ps.banned {
				delete(n.peers, did)
			}
		}
	}
}

// recordFailure settles one failure for a peer at the given event time and
// applies the ban policy.
func (n *Node) recordFailure(peer DID, at time.Time) {
	ps := n.peerRecord(peer)
	if ps.banned {
		return
	}
	ps.consecutiveFailures++
	if ps.consecutiveFailures >= banThreshold {
		ps.banned = true
		ps.banUntil = at.Add(banDuration)
		n.cancelPeerSessions(peer)
	}
}

// recordSuccess resets the peer's consecutive failure counter.
func (n *Node) recordSuccess(peer DID) {
	n.peerRecord(peer).consecutiveFailures = 0
}

// cancelPeerSessions cancels every pending session with the peer without
// counting additional failures.
func (n *Node) cancelPeerSessions(peer DID) {
	for _, s := range n.sessions {
		if s.state == StatePending && s.peer == peer {
			s.state = StateCancelled
		}
	}
}

// banned reports whether the peer is currently banned. Callers must sweep
// first so expired bans are already cleared.
func (n *Node) banned(peer DID) bool {
	ps, ok := n.peers[peer]
	return ok && ps.banned
}

// Session returns a snapshot of the session with the given id.
func (n *Node) Session(id [SessionIDLen]byte) (SessionInfo, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sweep(n.now())
	s, ok := n.sessions[id]
	if !ok {
		return SessionInfo{}, false
	}
	return SessionInfo{
		ID:       s.id,
		Peer:     s.peer,
		Role:     s.role,
		State:    s.state,
		Deadline: s.deadline,
	}, true
}

// PeerStatus returns a snapshot of a peer's standing.
func (n *Node) PeerStatus(peer DID) PeerStatus {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sweep(n.now())
	ps, ok := n.peers[peer]
	if !ok {
		return PeerStatus{}
	}
	return PeerStatus{
		ConsecutiveFailures: ps.consecutiveFailures,
		Banned:              ps.banned,
		BanUntil:            ps.banUntil,
	}
}
