# task26100282

TrustMesh 双向身份挑战库（Go）。机构节点在无中心身份提供方的情况下，
通过三步握手互相证明 Ed25519 身份，全部状态保存在进程内存中。

## 用法

```go
// 每个节点持有自己的 Ed25519 私钥及可信 DID -> 公钥的固定映射。
a := trustmesh.NewNode("did:a", privA, map[string]ed25519.PublicKey{"did:b": pubB})
b := trustmesh.NewNode("did:b", privB, map[string]ed25519.PublicKey{"did:a": pubA})

// 三步握手：报文由调用方负责传递。
inv,  _ := a.StartChallenge("did:b") // 1. 邀请：会话标识 + nonceA
resp, _ := b.HandleMessage(inv)      // 2. 响应：nonceB + 响应方证明
conf, _ := a.HandleMessage(resp)     // 3. 确认：发起方证明（a 本地成功）
b.HandleMessage(conf)                //    b 验过确认后本地成功

// 查询会话与对端状态。
view, ok := a.Session(inv.SessionID)
status  := a.PeerStatus("did:b")
```

## 语义要点

- 证明绑定协议用途、双方 DID、签名方角色、会话标识与两枚 nonce，
  不可跨会话、跨方向或跨对端复用。
- 各自从本地起点计时，须在严格小于 10 秒内完成本地认证；恰到 10 秒即超时。
- 会话终态不可反转，最多结算一次；合法重传返回原输出，不重复结算。
- 同一对端连续 5 次失败封禁 30 分钟，取消其余未结束会话；一次成功清零计数。
- 超时与解封按原截止时刻生效，与何时发现无关。

## 测试

```sh
go test ./...
```

测试通过 `WithClock` 注入可控时钟，覆盖重传幂等、跨会话/反射/跨对端证明拒绝、
恰 10 秒超时、同刻超时按会话标识字节序结算、封禁与解封时刻、迟到证明不复活等场景。
