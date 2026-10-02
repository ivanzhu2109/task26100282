package trustmesh

import (
	"testing"
	"time"
)

// TestTimeoutAtDeadline 严格小于 10 秒可完成，恰到 10 秒即超时。
func TestTimeoutAtDeadline(t *testing.T) {
	a, b, clk := newPair(t)

	inv := mustStart(t, a, "did:b")
	resp := mustHandle(t, b, inv)

	// 9.999 秒：仍未超时，发起方可正常完成。
	clk.advance(10*time.Second - time.Millisecond)
	conf := mustHandle(t, a, resp)
	if conf == nil {
		t.Fatal("handshake should complete just before 10s")
	}
	if got := stateOf(t, a, inv.SessionID); got != StateSucceeded {
		t.Fatalf("initiator state = %v, want succeeded", got)
	}

	// 响应方从接受邀请起计时；再推进到其 10 秒整，确认迟到即超时。
	clk.advance(time.Millisecond)
	if got := stateOf(t, b, inv.SessionID); got != StateFailed {
		t.Fatalf("responder state at exactly 10s = %v, want failed", got)
	}
	// 迟到的确认不能恢复已失败的会话。
	if reply := mustHandle(t, b, conf); reply != nil {
		t.Fatal("late confirm should have no reply")
	}
	if got := stateOf(t, b, inv.SessionID); got != StateFailed {
		t.Fatalf("late confirm revived session: %v", got)
	}
	if st := b.PeerStatus("did:a"); st.ConsecutiveFailures != 1 {
		t.Fatalf("failures = %d, want 1", st.ConsecutiveFailures)
	}
}

// TestIdleThenQueryTimeout 长时间没有调用后再查询，超时按原截止时刻生效。
func TestIdleThenQueryTimeout(t *testing.T) {
	a, _, clk := newPair(t)
	inv := mustStart(t, a, "did:b")
	deadline := clk.now().Add(SessionTimeout)

	// 闲置 1 小时无任何调用，再查询：会话已按原截止时刻失败。
	clk.advance(time.Hour)
	v, ok := a.Session(inv.SessionID)
	if !ok {
		t.Fatal("session missing")
	}
	if v.State != StateFailed {
		t.Fatalf("state = %v, want failed", v.State)
	}
	if !v.Deadline.Equal(deadline) {
		t.Fatalf("deadline moved: %v, want %v", v.Deadline, deadline)
	}
	if st := a.PeerStatus("did:b"); st.ConsecutiveFailures != 1 {
		t.Fatalf("failures = %d, want 1", st.ConsecutiveFailures)
	}
}

// failOnce 让 a 与 b 间产生一次失败（坏证明），返回会话 ID。
func failOnce(t *testing.T, a, b *Node) [NonceSize]byte {
	t.Helper()
	inv := mustStart(t, a, "did:b")
	resp := mustHandle(t, b, inv)
	bad := *resp
	bad.Proof = make([]byte, len(resp.Proof)) // 全零签名，校验必失败
	if reply := mustHandle(t, a, &bad); reply != nil {
		t.Fatal("bad proof should not produce a confirm")
	}
	if got := stateOf(t, a, inv.SessionID); got != StateFailed {
		t.Fatalf("state = %v, want failed", got)
	}
	return inv.SessionID
}

// TestBanAfterFiveFailures 连续 5 次失败立即封禁 30 分钟。
func TestBanAfterFiveFailures(t *testing.T) {
	a, b, clk := newPair(t)

	for i := 1; i <= 4; i++ {
		failOnce(t, a, b)
		st := a.PeerStatus("did:b")
		if st.Banned {
			t.Fatalf("banned after %d failures", i)
		}
		if st.ConsecutiveFailures != i {
			t.Fatalf("failures = %d, want %d", st.ConsecutiveFailures, i)
		}
	}
	// 第 5 次失败触发封禁，并取消其余未结束会话。
	openInv := mustStart(t, a, "did:b") // 保持未结束
	failOnce(t, a, b)
	st := a.PeerStatus("did:b")
	if !st.Banned {
		t.Fatal("peer should be banned after 5 consecutive failures")
	}
	wantUntil := clk.now().Add(BanDuration)
	if !st.BannedUntil.Equal(wantUntil) {
		t.Fatalf("bannedUntil = %v, want %v", st.BannedUntil, wantUntil)
	}
	if got := stateOf(t, a, openInv.SessionID); got != StateCancelled {
		t.Fatalf("open session = %v, want cancelled", got)
	}
	if st.ConsecutiveFailures != 5 {
		t.Fatalf("failures = %d, want 5 (cancel adds none)", st.ConsecutiveFailures)
	}

	// 封禁期间：拒绝新发起，入站报文被忽略，不延长封禁、不增加计数。
	if _, err := a.StartChallenge("did:b"); err != ErrPeerBanned {
		t.Fatalf("StartChallenge err = %v, want ErrPeerBanned", err)
	}
	invB := mustStart(t, b, "did:a") // b 侧不知道封禁，正常发起
	clk.advance(time.Minute)
	if reply := mustHandle(t, a, invB); reply != nil {
		t.Fatal("banned peer's invite should be ignored")
	}
	st = a.PeerStatus("did:b")
	if !st.Banned || !st.BannedUntil.Equal(wantUntil) {
		t.Fatalf("ban changed during ban: %+v", st)
	}

	// 到解封时刻：封禁按原截止时刻结束，计数清零；旧会话不能复活。
	clk.advance(28 * time.Minute)
	if st := a.PeerStatus("did:b"); !st.Banned {
		t.Fatal("ban lifted too early")
	}
	clk.advance(time.Minute) // 恰满 30 分钟
	st = a.PeerStatus("did:b")
	if st.Banned || st.ConsecutiveFailures != 0 {
		t.Fatalf("after unban: %+v", st)
	}
	if got := stateOf(t, a, openInv.SessionID); got != StateCancelled {
		t.Fatalf("old session revived: %v", got)
	}
	// 解封后 a 可重新发起挑战。
	if inv2 := mustStart(t, a, "did:b"); inv2 == nil {
		t.Fatal("StartChallenge after unban should succeed")
	}
	// 注意：b 侧因 a 此前放弃的响应会话超时，独立地对 a 计失败并封禁，
	// 这符合"双方只承诺本地认证结果"。
	if st := b.PeerStatus("did:a"); !st.Banned {
		t.Fatal("b should independently ban a after 5 expired responder sessions")
	}
}

// TestSuccessResetsFailures 一次成功清零连续失败数。
func TestSuccessResetsFailures(t *testing.T) {
	a, b, _ := newPair(t)
	for i := 0; i < 4; i++ {
		failOnce(t, a, b)
	}
	// 一次完整成功握手。
	inv := mustStart(t, a, "did:b")
	resp := mustHandle(t, b, inv)
	mustHandle(t, a, resp)
	if st := a.PeerStatus("did:b"); st.ConsecutiveFailures != 0 {
		t.Fatalf("failures = %d, want 0 after success", st.ConsecutiveFailures)
	}
	// 再失败 4 次不应封禁。
	for i := 0; i < 4; i++ {
		failOnce(t, a, b)
	}
	if st := a.PeerStatus("did:b"); st.Banned {
		t.Fatal("should not be banned: counter was reset by success")
	}
}

// TestSimultaneousTimeoutOrder 同刻超时按会话标识字节序结算：
// 第 5 次失败（字节序较小者）触发封禁，字节序较大者被取消而非失败。
func TestSimultaneousTimeoutOrder(t *testing.T) {
	a, b, clk := newPair(t)
	for i := 0; i < 4; i++ {
		failOnce(t, a, b)
	}
	// 同一时刻创建两个会话，截止时刻相同。
	inv1 := mustStart(t, a, "did:b")
	inv2 := mustStart(t, a, "did:b")
	small, big := inv1.SessionID, inv2.SessionID
	if !lessID(small, big) {
		small, big = big, small
	}
	clk.advance(SessionTimeout)
	if got := stateOf(t, a, small); got != StateFailed {
		t.Fatalf("bytewise-smaller session = %v, want failed (settled first)", got)
	}
	if got := stateOf(t, a, big); got != StateCancelled {
		t.Fatalf("bytewise-larger session = %v, want cancelled by ban", got)
	}
	st := a.PeerStatus("did:b")
	if !st.Banned {
		t.Fatal("peer should be banned")
	}
	// 封禁从第 5 次失败的原截止时刻起算，而非延迟发现时刻。
	wantUntil := clk.now().Add(BanDuration) // clk 恰推进 10s，截止时刻即当前
	if !st.BannedUntil.Equal(wantUntil) {
		t.Fatalf("bannedUntil = %v, want %v", st.BannedUntil, wantUntil)
	}
}

func lessID(x, y [NonceSize]byte) bool {
	for i := range x {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return false
}

// TestLateProofCannotRevive 迟到证明不能恢复已超时失败的旧会话。
func TestLateProofCannotRevive(t *testing.T) {
	a, b, clk := newPair(t)
	inv := mustStart(t, a, "did:b")
	resp := mustHandle(t, b, inv)

	// 双方均超时后再送达合法响应与确认。
	clk.advance(2 * SessionTimeout)
	if got := stateOf(t, a, inv.SessionID); got != StateFailed {
		t.Fatalf("initiator = %v, want failed", got)
	}
	if reply := mustHandle(t, a, resp); reply != nil {
		t.Fatal("late response should not produce confirm")
	}
	if got := stateOf(t, a, inv.SessionID); got != StateFailed {
		t.Fatalf("late response revived session: %v", got)
	}
}

// TestOtherPeersUnaffected 封禁只针对单个对端。
func TestOtherPeersUnaffected(t *testing.T) {
	a, b, _ := newPair(t)
	for i := 0; i < 5; i++ {
		failOnce(t, a, b)
	}
	if st := a.PeerStatus("did:b"); !st.Banned {
		t.Fatal("did:b should be banned")
	}
	// b 视角：a 不是被封禁方，b 的计数不受 a 侧封禁影响。
	if st := b.PeerStatus("did:a"); st.Banned || st.ConsecutiveFailures != 0 {
		t.Fatalf("b's view of a: %+v", st)
	}
}
