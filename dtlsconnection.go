package webrtc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/notedit/sdp"
	"github.com/notedit/webrtc-server/packet"
	"github.com/pion/dtls/v2"
	"github.com/pion/srtp"
)

func init() {

	//
}

type DTLSConnection struct {
	sync.RWMutex

	privateKey crypto.PrivateKey
	x509Cert   *x509.Certificate

	remoteParameters  *sdp.DTLSInfo
	remoteCertificate []byte

	conn *dtls.Conn

	packetsIn  chan *packet.UDP
	packetsOut chan *packet.UDP

	srtpSession  *srtp.SessionSRTP
	srtcpSession *srtp.SessionSRTCP

	localSetup        sdp.Setup
	remoteSetup       sdp.Setup
	remoteHash        string
	remoteFingerprint string
}

func NewDTLSConnection() *DTLSConnection {

	dtls := &DTLSConnection{}
	dtls.packetsIn = make(chan *packet.UDP, 5)
	dtls.packetsOut = make(chan *packet.UDP, 5)
	dtls.remoteParameters = &sdp.DTLSInfo{}
	dtls.localSetup = sdp.SETUPPASSIVE

	return dtls
}

func (d *DTLSConnection) Init() error {

	return nil
}

// SetSRTPProtectionProfiles  options
func (d *DTLSConnection) SetSRTPProtectionProfiles() {

	// options
}

// SetRemoteSetup set remote setup
func (d *DTLSConnection) SetRemoteSetup(setup sdp.Setup) {
	d.remoteSetup = setup
}

// SetRemoteFingerprint set remote dtls
func (d *DTLSConnection) SetRemoteFingerprint(hash string, fingerprint string) {
	d.remoteHash = hash
	d.remoteFingerprint = fingerprint
}

// GenerateCertificate generate a local certificate
func (d *DTLSConnection) GenerateCertificate() {

	secretKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		panic(err)
	}

	origin := make([]byte, 16)

	_, err = rand.Read(origin)

	if err != nil {
		panic(err)
	}

	// Max random value, a 130-bits integer, i.e 2^130 - 1
	maxBigInt := new(big.Int)
	/* #nosec */
	maxBigInt.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(maxBigInt, big.NewInt(1))
	/* #nosec */
	serialNumber, err := rand.Int(rand.Reader, maxBigInt)
	if err != nil {
		panic(err)
	}

	certificate := x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		NotBefore:             time.Now(),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		NotAfter:              time.Now().AddDate(0, 1, 0),
		SerialNumber:          serialNumber,
		Version:               2,
		Subject:               pkix.Name{CommonName: hex.EncodeToString(origin)},
		IsCA:                  true,
	}

	x509Cert, err := newCertificate(secretKey, certificate)

	d.privateKey = secretKey
	d.x509Cert = x509Cert
}

func (d *DTLSConnection) Close() {

}

func (d *DTLSConnection) Write(data []byte) (int, error) {

	packet := packet.NewUDPFromData(data, nil)
	d.packetsOut <- packet

	return len(data), nil
}

func (d *DTLSConnection) Read(data []byte) (int, error) {

	packet := <-d.packetsIn

	if len(data) < packet.GetSize() {
		return 0, io.ErrShortBuffer
	}

	n := copy(data, packet.GetData())

	return n, nil
}

// SetDeadline net.Conn interface
func (d *DTLSConnection) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline net.Conn interface
func (d *DTLSConnection) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline net.Conn interface
func (d *DTLSConnection) SetWriteDeadline(t time.Time) error {
	return nil
}

// LocalAddr net.Conn interface
func (d *DTLSConnection) LocalAddr() net.Addr {
	return nil
}

// RemoteAddr net.Conn interface
func (d *DTLSConnection) RemoteAddr() net.Addr {
	return nil
}

func newCertificate(key crypto.PrivateKey, tpl x509.Certificate) (*x509.Certificate, error) {
	var err error
	var certDER []byte
	switch sk := key.(type) {
	case *rsa.PrivateKey:
		pk := sk.Public()
		tpl.SignatureAlgorithm = x509.SHA256WithRSA
		certDER, err = x509.CreateCertificate(rand.Reader, &tpl, &tpl, pk, sk)
		if err != nil {
			return nil, err
		}
	case *ecdsa.PrivateKey:
		pk := sk.Public()
		tpl.SignatureAlgorithm = x509.ECDSAWithSHA256
		certDER, err = x509.CreateCertificate(rand.Reader, &tpl, &tpl, pk, sk)
		if err != nil {
			return nil, err
		}
	default:
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return cert, nil
}
