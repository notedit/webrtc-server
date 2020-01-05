package webrtc

import "net"

type ICEState int

const (
	ICEStateInitial ICEState = iota + 1
	ICEStateChecking
	ICEStateConnected
)

type ICERemoteCandidate struct {
	addr  *net.Addr
	state ICEState
}

func NewRemoteCandidate(addr *net.Addr) *ICERemoteCandidate {
	candidate := &ICERemoteCandidate{}
	candidate.addr = addr
	return candidate
}
