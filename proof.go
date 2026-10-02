package trustmesh

import (
	"crypto/ed25519"
	"encoding/binary"
)

// proofDomain separates TrustMesh proofs from any other use of the keys.
const proofDomain = "TrustMesh/1/proof"

// proofTranscript builds the exact byte string that is signed. It binds the
// protocol purpose, both DIDs, the signer's role, the session id and both
// nonces, so a proof cannot be replayed across sessions, directions or peers.
func proofTranscript(role Role, initiator, responder DID, sessionID [SessionIDLen]byte, nonceA, nonceB [NonceLen]byte) []byte {
	var buf []byte
	buf = appendLenPrefixed(buf, []byte(proofDomain))
	roleByte := byte(0)
	if role == RoleResponder {
		roleByte = 1
	}
	buf = append(buf, roleByte)
	buf = appendLenPrefixed(buf, []byte(initiator))
	buf = appendLenPrefixed(buf, []byte(responder))
	buf = append(buf, sessionID[:]...)
	buf = append(buf, nonceA[:]...)
	buf = append(buf, nonceB[:]...)
	return buf
}

func appendLenPrefixed(buf, data []byte) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(data)))
	buf = append(buf, n[:]...)
	return append(buf, data...)
}

// signProof signs the transcript for the given role with the node's key.
func signProof(priv ed25519.PrivateKey, role Role, initiator, responder DID, sessionID [SessionIDLen]byte, nonceA, nonceB [NonceLen]byte) []byte {
	return ed25519.Sign(priv, proofTranscript(role, initiator, responder, sessionID, nonceA, nonceB))
}

// verifyProof checks a proof against the expected transcript and signer key.
func verifyProof(pub ed25519.PublicKey, role Role, initiator, responder DID, sessionID [SessionIDLen]byte, nonceA, nonceB [NonceLen]byte, proof []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(pub, proofTranscript(role, initiator, responder, sessionID, nonceA, nonceB), proof)
}
