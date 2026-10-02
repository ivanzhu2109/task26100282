package trustmesh

import (
	"crypto/ed25519"
	"encoding/binary"
)

// proofMessage 构造待签名的绑定内容：
// 协议用途域 || 签名方角色 || 会话标识 || nonceA || nonceB || 发起方DID || 响应方DID。
// 证明因此无法跨会话、跨方向或跨对端使用。
func proofMessage(role byte, sessionID, nonceA, nonceB [NonceSize]byte, initiatorDID, responderDID string) []byte {
	buf := make([]byte, 0, len(proofDomain)+1+3*NonceSize+len(initiatorDID)+len(responderDID)+8)
	buf = append(buf, proofDomain...)
	buf = append(buf, role)
	buf = append(buf, sessionID[:]...)
	buf = append(buf, nonceA[:]...)
	buf = append(buf, nonceB[:]...)
	buf = appendDID(buf, initiatorDID)
	buf = appendDID(buf, responderDID)
	return buf
}

func appendDID(buf []byte, did string) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(did)))
	buf = append(buf, l[:]...)
	return append(buf, did...)
}

// signProof 用本节点私钥对绑定内容签名。
func signProof(priv ed25519.PrivateKey, role byte, sessionID, nonceA, nonceB [NonceSize]byte, initiatorDID, responderDID string) []byte {
	msg := proofMessage(role, sessionID, nonceA, nonceB, initiatorDID, responderDID)
	return ed25519.Sign(priv, msg)
}

// verifyProof 校验证明的签名与全部绑定内容。
func verifyProof(pub ed25519.PublicKey, role byte, sessionID, nonceA, nonceB [NonceSize]byte, initiatorDID, responderDID string, proof []byte) bool {
	if pub == nil || len(proof) != ed25519.SignatureSize {
		return false
	}
	msg := proofMessage(role, sessionID, nonceA, nonceB, initiatorDID, responderDID)
	return ed25519.Verify(pub, msg, proof)
}
