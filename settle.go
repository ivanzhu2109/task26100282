package trustmesh

import (
	"bytes"
	"sort"
	"time"
)

// peer 返回对端内部状态，不存在则创建。
func (n *Node) peer(did string) *peerState {
	p, ok := n.peers[did]
	if !ok {
		p = &peerState{}
		n.peers[did] = p
	}
	return p
}

// bannedLocked 判断对端当前是否处于封禁期（调用前须已 sweep）。
func (n *Node) bannedLocked(did string) bool {
	p, ok := n.peers[did]
	if !ok {
		return false
	}
	return !p.bannedUntil.IsZero() && n.now().Before(p.bannedUntil)
}

// sweepLocked 在处理当前操作前，按原截止时刻结算已到期事件：
// 先解封到期的封禁，再按会话标识字节序结算已到期的未结束会话。
// 超时失败以其原截止时刻生效，不从延迟发现的时刻重新起算。
func (n *Node) sweepLocked() {
	now := n.now()
	for _, p := range n.peers {
		if !p.bannedUntil.IsZero() && !now.Before(p.bannedUntil) {
			p.bannedUntil = time.Time{}
			p.consecutiveFailures = 0
		}
	}
	var expired []*session
	for _, s := range n.sessions {
		if s.state == StatePending && !now.Before(s.deadline) {
			expired = append(expired, s)
		}
	}
	sort.Slice(expired, func(i, j int) bool {
		return bytes.Compare(expired[i].id[:], expired[j].id[:]) < 0
	})
	for _, s := range expired {
		n.failSessionLocked(s, s.deadline)
	}
}

// failSessionLocked 结算一次失败：终态不可反转，每个会话最多结算一次。
// at 为失败生效时刻。同一对端连续失败达到阈值立即封禁，
// 并取消该对端其余未结束会话，取消不额外计失败。
func (n *Node) failSessionLocked(s *session, at time.Time) {
	if s.state != StatePending {
		return
	}
	s.state = StateFailed
	p := n.peer(s.peerDID)
	p.consecutiveFailures++
	if p.consecutiveFailures >= MaxConsecutiveFailures && !n.bannedLocked(s.peerDID) {
		p.bannedUntil = at.Add(BanDuration)
		for _, other := range n.sessions {
			if other.peerDID == s.peerDID && other.state == StatePending {
				other.state = StateCancelled
			}
		}
	}
}

// succeedSessionLocked 结算一次成功，并清零该对端连续失败数。
func (n *Node) succeedSessionLocked(s *session) {
	if s.state != StatePending {
		return
	}
	s.state = StateSucceeded
	n.peer(s.peerDID).consecutiveFailures = 0
}
