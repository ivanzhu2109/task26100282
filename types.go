package trustmesh

import "time"

const (
	SessionIDLen = 32
	NonceLen     = 32
)

const (
	authTimeout  = 10 * time.Second
	banDuration  = 30 * time.Minute
	banThreshold = 5
)

// DID identifies an institution node.
type DID string

// Role is the local node's role in a session.
type Role int

const (
	RoleInitiator Role = iota
	RoleResponder
)

// MessageType identifies the handshake step a message belongs to.
type MessageType int

const (
	MsgInvite MessageType = iota
	MsgResponse
	MsgConfirm
)

// Message is a handshake packet handed to the caller for transport.
type Message struct {
	Type      MessageType
	SessionID [SessionIDLen]byte
	From      DID
	NonceA    [NonceLen]byte
	NonceB    [NonceLen]byte
	Proof     []byte
}

// SessionState is the terminal-aware lifecycle state of a session.
type SessionState int

const (
	StatePending SessionState = iota
	StateSucceeded
	StateFailed
	StateCancelled
	StateExpired
)

// Terminal reports whether the state can never change again.
func (s SessionState) Terminal() bool { return s != StatePending }

// SessionInfo is a read-only snapshot of a session.
type SessionInfo struct {
	ID       [SessionIDLen]byte
	Peer     DID
	Role     Role
	State    SessionState
	Deadline time.Time
}

// PeerStatus is a read-only snapshot of a peer's standing.
type PeerStatus struct {
	ConsecutiveFailures int
	Banned              bool
	BanUntil            time.Time
}
