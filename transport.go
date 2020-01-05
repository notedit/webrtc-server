package webrtc

import (
	"net"
	"sync"

	"github.com/notedit/sdp"
	"github.com/notedit/webrtc-server/packet"
)

type Transport struct {
	localIce         *sdp.ICEInfo
	localDtls        *sdp.DTLSInfo
	localCandidates  []*sdp.CandidateInfo
	remoteIce        *sdp.ICEInfo
	remoteDtls       *sdp.DTLSInfo
	remoteCandidates []*sdp.CandidateInfo
	dtlsState        string

	iceLocalUsername string
	iceLocalPassword string

	iceRemoteUsername string
	iceRemotePassword string

	dtls     *DTLSConnection
	active   *net.UDPAddr
	username string
	sync.Mutex
}

func (t *Transport) ActivateRemoteCandidate(addr *net.UDPAddr) {
	t.active = addr
}

func (t *Transport) HasActiveRemoteCandidate() bool {
	if t.active == nil {
		return false
	}
	return true
}

func (t *Transport) onData(packet *packet.UDP) {

	if packet.IsDTLS() {
		// handle dtls
		return
	}

	if packet.IsRTCP() {

	}
}

func (t *Transport) SetRemoteCryptoDTLS(dtlsInfo *sdp.DTLSInfo) error {

	t.dtls.SetRemoteSetup(dtlsInfo.GetSetup())
	t.dtls.SetRemoteFingerprint(dtlsInfo.GetHash(), dtlsInfo.GetFingerprint())

	return t.dtls.Init()
}

func (t *Transport) SetRemoteCryptoSDES() error {

	return nil
}

func (t *Transport) SetLocalCryptoSDES() error {

	return nil
}

func (t *Transport) SetLocalSTUNCredentials(username string, password string) {

	t.iceLocalUsername = username
	t.iceLocalPassword = password
}

func (t *Transport) SetRemoteSTUNCredentials(username string, password string) {

	t.iceRemoteUsername = username
	t.iceRemotePassword = password
}
