package trustmesh

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

// testClock 可手动推进的时钟。
type testClock struct{ t time.Time }

func (c *testClock) now() time.Time          { return c.t }
func (c *testClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// keyPair 生成测试密钥。
func keyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// newPair 创建一对互信的节点及共享时钟。
func newPair(t *testing.T) (*Node, *Node, *testClock) {
	t.Helper()
	pubA, privA := keyPair(t)
	pubB, privB := keyPair(t)
	clk := &testClock{t: time.Now()}
	a := NewNode("did:a", privA,
		map[string]ed25519.PublicKey{"did:b": pubB}, WithClock(clk.now))
	b := NewNode("did:b", privB,
		map[string]ed25519.PublicKey{"did:a": pubA}, WithClock(clk.now))
	return a, b, clk
}

// mustStart 发起挑战并返回邀请报文。
func mustStart(t *testing.T, n *Node, peer string) *Message {
	t.Helper()
	inv, err := n.StartChallenge(peer)
	if err != nil {
		t.Fatalf("StartChallenge: %v", err)
	}
	return inv
}

// mustHandle 处理报文并要求无错误。
func mustHandle(t *testing.T, n *Node, msg *Message) *Message {
	t.Helper()
	reply, err := n.HandleMessage(msg)
	if err != nil {
		t.Fatalf("HandleMessage: %v", err)
	}
	return reply
}

func stateOf(t *testing.T, n *Node, id [NonceSize]byte) SessionState {
	t.Helper()
	v, ok := n.Session(id)
	if !ok {
		t.Fatalf("session %x not found", id[:8])
	}
	return v.State
}

// TestHandshakeSuccess 验证三步握手双方在各自步骤成功。
func TestHandshakeSuccess(t *testing.T) {
	a, b, _ := newPair(t)

	inv := mustStart(t, a, "did:b")
	resp := mustHandle(t, b, inv)
	if resp == nil || resp.Type != MsgResponse {
		t.Fatal("responder should return MsgResponse")
	}
	// 发起方验过响应后在本地成功并返回确认。
	conf := mustHandle(t, a, resp)
	if conf == nil || conf.Type != MsgConfirm {
		t.Fatal("initiator should return MsgConfirm")
	}
	if got := stateOf(t, a, inv.SessionID); got != StateSucceeded {
		t.Fatalf("initiator state = %v, want succeeded", got)
	}
	// 响应方此时仍未成功，验过确认后才成功。
	if got := stateOf(t, b, inv.SessionID); got != StatePending {
		t.Fatalf("responder state before confirm = %v, want pending", got)
	}
	if reply := mustHandle(t, b, conf); reply != nil {
		t.Fatal("confirm should have no reply")
	}
	if got := stateOf(t, b, inv.SessionID); got != StateSucceeded {
		t.Fatalf("responder state = %v, want succeeded", got)
	}
}

// TestRetransmission 验证各步骤重传返回原输出且不重复结算。
func TestRetransmission(t *testing.T) {
	a, b, _ := newPair(t)

	inv := mustStart(t, a, "did:b")
	resp1 := mustHandle(t, b, inv)
	sessionsBefore := len(b.sessions)
	// 邀请重传：返回原响应，不创建第二个会话，不更换 nonce。
	resp2 := mustHandle(t, b, inv)
	if len(b.sessions) != sessionsBefore {
		t.Fatal("invite retransmission created a second session")
	}
	if resp2.NonceB != resp1.NonceB || string(resp2.Proof) != string(resp1.Proof) {
		t.Fatal("invite retransmission changed nonce or proof")
	}

	conf1 := mustHandle(t, a, resp1)
	// 响应重传：发起方已成功，返回原确认，不重复结算。
	conf2 := mustHandle(t, a, resp1)
	if conf2 == nil || string(conf2.Proof) != string(conf1.Proof) {
		t.Fatal("response retransmission should return original confirm")
	}
	if got := stateOf(t, a, inv.SessionID); got != StateSucceeded {
		t.Fatalf("initiator state = %v, want succeeded", got)
	}

	mustHandle(t, b, conf1)
	// 确认重传：响应方已成功，无输出，状态不变。
	if reply := mustHandle(t, b, conf1); reply != nil {
		t.Fatal("confirm retransmission should have no reply")
	}
	if got := stateOf(t, b, inv.SessionID); got != StateSucceeded {
		t.Fatalf("responder state = %v, want succeeded", got)
	}
	if st := a.PeerStatus("did:b"); st.ConsecutiveFailures != 0 {
		t.Fatalf("unexpected failures: %d", st.ConsecutiveFailures)
	}
	if st := b.PeerStatus("did:a"); st.ConsecutiveFailures != 0 {
		t.Fatalf("unexpected failures: %d", st.ConsecutiveFailures)
	}
}

// TestCrossSessionProofRejected 跨会话复用证明不能成功，且结算一次失败。
func TestCrossSessionProofRejected(t *testing.T) {
	a, b, _ := newPair(t)

	// 会话 1 正常完成，取得响应方证明。
	inv1 := mustStart(t, a, "did:b")
	resp1 := mustHandle(t, b, inv1)

	// 会话 2：把会话 1 的响应证明重放到会话 2。
	inv2 := mustStart(t, a, "did:b")
	resp2 := mustHandle(t, b, inv2)
	forged := *resp2
	forged.Proof = resp1.Proof
	if reply := mustHandle(t, a, &forged); reply != nil {
		t.Fatal("cross-session proof should not produce a confirm")
	}
	if got := stateOf(t, a, inv2.SessionID); got != StateFailed {
		t.Fatalf("session2 state = %v, want failed", got)
	}
	if st := a.PeerStatus("did:b"); st.ConsecutiveFailures != 1 {
		t.Fatalf("failures = %d, want 1", st.ConsecutiveFailures)
	}
	// 会话 1 不受影响。
	if got := stateOf(t, a, inv1.SessionID); got != StatePending {
		t.Fatalf("session1 state = %v, want pending", got)
	}
}

// TestReflectedProofRejected 反射证明（把发起方证明当作响应方证明）不能成功。
func TestReflectedProofRejected(t *testing.T) {
	a, b, _ := newPair(t)

	// 完成一次握手，拿到发起方的确认证明。
	inv1 := mustStart(t, a, "did:b")
	resp1 := mustHandle(t, b, inv1)
	conf1 := mustHandle(t, a, resp1)

	// 新会话：把发起方证明反射回发起方，冒充响应方证明。
	inv2 := mustStart(t, a, "did:b")
	mustHandle(t, b, inv2) // b 正常建会话
	reflected := &Message{
		Type:      MsgResponse,
		From:      "did:b",
		SessionID: inv2.SessionID,
		NonceB:    randNonce(),
		Proof:     conf1.Proof, // 角色不符的反射证明
	}
	if reply := mustHandle(t, a, reflected); reply != nil {
		t.Fatal("reflected proof should not produce a confirm")
	}
	if got := stateOf(t, a, inv2.SessionID); got != StateFailed {
		t.Fatalf("session2 state = %v, want failed", got)
	}
}

// TestCrossPeerProofRejected 跨对端复用证明不能成功。
func TestCrossPeerProofRejected(t *testing.T) {
	a, b, _ := newPair(t)
	// 第三方节点 c，也信任 a。
	pubC, privC := keyPair(t)
	clk := &testClock{t: time.Now()}
	_ = pubC
	c := NewNode("did:c", privC,
		map[string]ed25519.PublicKey{"did:a": mustPubOf(t, a)}, WithClock(clk.now))
	_ = c

	// a 与 b 的会话中取得的响应方证明，被重放到 a 与 c 的会话。
	invB := mustStart(t, a, "did:b")
	respB := mustHandle(t, b, invB)

	// a 向 c 发起挑战需要 a 信任 c；重新构造含 c 的 a 节点。
	a2 := NewNode("did:a", mustPrivOf(t, a),
		map[string]ed25519.PublicKey{"did:b": mustPubOf(t, b), "did:c": pubC},
		WithClock(clk.now))
	invC := mustStart(t, a2, "did:c")
	respC := mustHandle(t, c, invC)
	forged := *respC
	forged.Proof = respB.Proof // b 的证明绑定 did:b，不能用于 did:c
	if reply := mustHandle(t, a2, &forged); reply != nil {
		t.Fatal("cross-peer proof should not produce a confirm")
	}
	if got := stateOf(t, a2, invC.SessionID); got != StateFailed {
		t.Fatalf("session state = %v, want failed", got)
	}
}

// mustPubOf / mustPrivOf 从节点取密钥（白盒测试辅助）。
func mustPubOf(t *testing.T, n *Node) ed25519.PublicKey {
	t.Helper()
	return n.priv.Public().(ed25519.PublicKey)
}

func mustPrivOf(t *testing.T, n *Node) ed25519.PrivateKey {
	t.Helper()
	return n.priv
}

// TestUnknownMessageIgnored 无法定位既有会话的非邀请报文被忽略。
func TestUnknownMessageIgnored(t *testing.T) {
	a, _, _ := newPair(t)
	ghost := &Message{Type: MsgConfirm, From: "did:b", SessionID: randNonce(), Proof: make([]byte, 64)}
	if reply := mustHandle(t, a, ghost); reply != nil {
		t.Fatal("orphan confirm should be ignored")
	}
	if st := a.PeerStatus("did:b"); st.ConsecutiveFailures != 0 {
		t.Fatalf("orphan message should not count failures, got %d", st.ConsecutiveFailures)
	}
}
