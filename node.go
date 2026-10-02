package trustmesh

import (
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"time"
)

// Node 是一个 TrustMesh 机构节点，全部状态保存在进程内存中。
type Node struct {
	mu       sync.Mutex
	selfDID  string
	priv     ed25519.PrivateKey
	trusted  map[string]ed25519.PublicKey
	sessions map[[NonceSize]byte]*session
	peers    map[string]*peerState
	now      func() time.Time
}

// Option 可选配置（主要用于测试注入时钟）。
type Option func(*Node)

// WithClock 注入时间源，默认使用本机单调时间 time.Now。
func WithClock(now func() time.Time) Option {
	return func(n *Node) { n.now = now }
}

// NewNode 创建节点。selfDID 为本节点 DID，priv 为本节点 Ed25519 私钥，
// trusted 为可信 DID 到公钥的固定映射。
func NewNode(selfDID string, priv ed25519.PrivateKey, trusted map[string]ed25519.PublicKey, opts ...Option) *Node {
	n := &Node{
		selfDID:  selfDID,
		priv:     priv,
		trusted:  make(map[string]ed25519.PublicKey, len(trusted)),
		sessions: make(map[[NonceSize]byte]*session),
		peers:    make(map[string]*peerState),
		now:      time.Now,
	}
	for did, pub := range trusted {
		n.trusted[did] = pub
	}
	for _, opt := range opts {
		opt(n)
	}
	return n
}

// StartChallenge 向指定对端发起挑战，返回需交给对方的 Invite 报文。
func (n *Node) StartChallenge(peerDID string) (*Message, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sweepLocked()
	if _, ok := n.trusted[peerDID]; !ok {
		return nil, ErrUnknownPeer
	}
	if n.bannedLocked(peerDID) {
		return nil, ErrPeerBanned
	}
	s := &session{
		id:       randNonce(),
		peerDID:  peerDID,
		role:     RoleInitiator,
		state:    StatePending,
		nonceA:   randNonce(),
		deadline: n.now().Add(SessionTimeout),
	}
	n.sessions[s.id] = s
	return &Message{
		Type:      MsgInvite,
		From:      n.selfDID,
		SessionID: s.id,
		NonceA:    s.nonceA,
	}, nil
}

// HandleMessage 处理入站报文，返回需回给对方的报文；无需回复时返回 nil。
func (n *Node) HandleMessage(msg *Message) (*Message, error) {
	if msg == nil {
		return nil, nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sweepLocked()
	peerPub, ok := n.trusted[msg.From]
	if !ok {
		return nil, nil // 非可信对端，忽略
	}
	if n.bannedLocked(msg.From) {
		return nil, nil // 封禁期间拒绝全部入站报文，不延长封禁、不增加计数
	}
	switch msg.Type {
	case MsgInvite:
		return n.handleInviteLocked(msg)
	case MsgResponse:
		return n.handleResponseLocked(msg, peerPub), nil
	case MsgConfirm:
		return n.handleConfirmLocked(msg, peerPub), nil
	}
	return nil, nil
}

// handleInviteLocked 处理邀请。重传邀请返回原响应，不创建第二个会话。
func (n *Node) handleInviteLocked(msg *Message) (*Message, error) {
	if s, ok := n.sessions[msg.SessionID]; ok {
		if s.role == RoleResponder && s.peerDID == msg.From &&
			s.nonceA == msg.NonceA && s.state == StatePending {
			return s.lastReply, nil // 完全相同的合法重传：返回原输出
		}
		return nil, nil // 会话标识冲突或已终态，忽略
	}
	s := &session{
		id:       msg.SessionID,
		peerDID:  msg.From,
		role:     RoleResponder,
		state:    StatePending,
		nonceA:   msg.NonceA,
		nonceB:   randNonce(),
		deadline: n.now().Add(SessionTimeout),
	}
	n.sessions[s.id] = s
	reply := &Message{
		Type:      MsgResponse,
		From:      n.selfDID,
		SessionID: s.id,
		NonceB:    s.nonceB,
		Proof: signProof(n.priv, proofRoleResponder, s.id, s.nonceA, s.nonceB,
			msg.From, n.selfDID),
	}
	s.lastReply = reply
	return reply, nil
}

// handleResponseLocked 发起方处理响应：验过证明后返回自己的证明并在本地成功。
func (n *Node) handleResponseLocked(msg *Message, peerPub ed25519.PublicKey) *Message {
	s, ok := n.sessions[msg.SessionID]
	if !ok || s.role != RoleInitiator || s.peerDID != msg.From {
		return nil // 无法定位既有会话的非邀请报文忽略
	}
	if s.state != StatePending {
		if s.state == StateSucceeded && s.nonceB == msg.NonceB {
			return s.lastReply // 完全相同的合法重传：返回原输出
		}
		return nil
	}
	if !verifyProof(peerPub, proofRoleResponder, s.id, s.nonceA, msg.NonceB,
		n.selfDID, msg.From, msg.Proof) {
		n.failSessionLocked(s, n.now())
		return nil
	}
	s.nonceB = msg.NonceB
	reply := &Message{
		Type:      MsgConfirm,
		From:      n.selfDID,
		SessionID: s.id,
		Proof: signProof(n.priv, proofRoleInitiator, s.id, s.nonceA, s.nonceB,
			n.selfDID, msg.From),
	}
	s.lastReply = reply
	n.succeedSessionLocked(s)
	return reply
}

// handleConfirmLocked 响应方处理确认：验过证明后才在本地成功。
func (n *Node) handleConfirmLocked(msg *Message, peerPub ed25519.PublicKey) *Message {
	s, ok := n.sessions[msg.SessionID]
	if !ok || s.role != RoleResponder || s.peerDID != msg.From {
		return nil
	}
	if s.state != StatePending {
		return nil // 终态不可反转；重传确认的原输出为空
	}
	if !verifyProof(peerPub, proofRoleInitiator, s.id, s.nonceA, s.nonceB,
		msg.From, n.selfDID, msg.Proof) {
		n.failSessionLocked(s, n.now())
		return nil
	}
	n.succeedSessionLocked(s)
	return nil
}

// Session 查询会话状态。
func (n *Node) Session(id [NonceSize]byte) (SessionView, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sweepLocked()
	s, ok := n.sessions[id]
	if !ok {
		return SessionView{}, false
	}
	return SessionView{
		SessionID: s.id,
		PeerDID:   s.peerDID,
		Role:      s.role,
		State:     s.state,
		Deadline:  s.deadline,
	}, true
}

// PeerStatus 查询对端状态。
func (n *Node) PeerStatus(did string) PeerStatus {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sweepLocked()
	st := PeerStatus{DID: did}
	if p, ok := n.peers[did]; ok {
		st.ConsecutiveFailures = p.consecutiveFailures
		if !p.bannedUntil.IsZero() && n.now().Before(p.bannedUntil) {
			st.Banned = true
			st.BannedUntil = p.bannedUntil
		}
	}
	return st
}

// randNonce 生成 256 位密码学安全随机值。
func randNonce() [NonceSize]byte {
	var b [NonceSize]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("trustmesh: crypto/rand unavailable: " + err.Error())
	}
	return b
}
