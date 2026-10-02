package trustmesh

import (
	"errors"
	"time"
)

// 协议常量
const (
	// NonceSize 会话标识与 nonce 的字节长度（256 位）。
	NonceSize = 32
	// SessionTimeout 本地认证必须在严格小于该时长内完成。
	SessionTimeout = 10 * time.Second
	// BanDuration 连续失败达到阈值后的封禁时长。
	BanDuration = 30 * time.Minute
	// MaxConsecutiveFailures 触发封禁的同一对端连续失败次数。
	MaxConsecutiveFailures = 5
)

// 错误定义
var (
	ErrUnknownPeer   = errors.New("trustmesh: unknown peer DID")
	ErrPeerBanned    = errors.New("trustmesh: peer is banned")
	ErrNoSession     = errors.New("trustmesh: no such session")
	ErrSessionClosed = errors.New("trustmesh: session already settled")
)

// MessageType 报文类型。
type MessageType uint8

const (
	MsgInvite   MessageType = 1 // 发起方 -> 响应方：会话标识 + nonceA
	MsgResponse MessageType = 2 // 响应方 -> 发起方：nonceB + 响应方证明
	MsgConfirm  MessageType = 3 // 发起方 -> 响应方：发起方证明
)

// Message 节点间传递的报文，由调用方负责传输。
type Message struct {
	Type      MessageType
	From      string // 发送方 DID
	SessionID [NonceSize]byte
	NonceA    [NonceSize]byte // 仅 Invite 携带
	NonceB    [NonceSize]byte // 仅 Response 携带
	Proof     []byte          // Response / Confirm 携带的 Ed25519 签名
}

// SessionState 会话状态。
type SessionState uint8

const (
	StatePending   SessionState = iota // 未结束
	StateSucceeded                     // 本地认证成功（终态）
	StateFailed                        // 本地认证失败（终态）
	StateCancelled                     // 因对端被封禁而取消（终态）
)

// SessionView 会话的对外只读视图。
type SessionView struct {
	SessionID [NonceSize]byte
	PeerDID   string
	Role      Role
	State     SessionState
	Deadline  time.Time
}

// Role 会话中的本地角色。
type Role uint8

const (
	RoleInitiator Role = iota + 1
	RoleResponder
)

// PeerStatus 对端状态。
type PeerStatus struct {
	DID                 string
	ConsecutiveFailures int
	Banned              bool
	BannedUntil         time.Time
}

// proof 绑定用的角色标识。
const (
	proofRoleResponder byte = 1
	proofRoleInitiator byte = 2
)

// proofDomain 协议用途域分隔串。
const proofDomain = "trustmesh-auth-v1"

// session 内部会话记录。
type session struct {
	id        [NonceSize]byte
	peerDID   string
	role      Role
	state     SessionState
	nonceA    [NonceSize]byte
	nonceB    [NonceSize]byte
	deadline  time.Time
	lastReply *Message // 重传时返回的原输出
}

// peerState 对端内部状态。
type peerState struct {
	consecutiveFailures int
	bannedUntil         time.Time
}
