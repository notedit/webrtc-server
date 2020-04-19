package webrtc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/notedit/sdp"
	"github.com/pion/dtls/v2"
	"github.com/pion/srtp"

	"github.com/pion/transport/packetio"
)

const maxBufferSize = 1000 * 1000

type dtlsendpoint struct {
	outbuffer *packetio.Buffer
	inbuffer  *packetio.Buffer
}

func (e *dtlsendpoint) Close() (err error) {

	return nil
}

func (e *dtlsendpoint) Read(data []byte) (int, error) {

	return 0, nil
}

func (e *dtlsendpoint) Write(data []byte) (int, error) {

	return 0, nil
}

// LocalAddr is a stub
func (e *dtlsendpoint) LocalAddr() net.Addr {
	return nil
}

// RemoteAddr is a stub
func (e *dtlsendpoint) RemoteAddr() net.Addr {
	return nil
}

// SetDeadline is a stub
func (e *dtlsendpoint) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline is a stub
func (e *dtlsendpoint) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline is a stub
func (e *dtlsendpoint) SetWriteDeadline(t time.Time) error {
	return nil
}

type DTLSConnection struct {
	lock sync.RWMutex

	privateKey crypto.PrivateKey
	x509Cert   *x509.Certificate

	remoteParameters  *sdp.DTLSInfo
	remoteCertificate []byte

	conn *dtls.Conn

	entpoint     *dtlsendpoint
	srtpSession  *srtp.SessionSRTP
	srtcpSession *srtp.SessionSRTCP

	localSetup        sdp.Setup
	remoteSetup       sdp.Setup
	remoteHash        string
	remoteFingerprint string
}

func NewDTLSConnection() *DTLSConnection {

	dtls := &DTLSConnection{}
	dtls.remoteParameters = &sdp.DTLSInfo{}
	dtls.localSetup = sdp.SETUPPASSIVE

	endpoint := &dtlsendpoint{}
	endpoint.inbuffer = packetio.NewBuffer()
	endpoint.outbuffer = packetio.NewBuffer()
	endpoint.inbuffer.SetLimitSize(maxBufferSize)
	endpoint.outbuffer.SetLimitSize(maxBufferSize)

	dtls.entpoint = endpoint
	return dtls
}

func (d *DTLSConnection) Init() error {

	return nil
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

func (d *DTLSConnection) SetRemoteDTLS(dtls *sdp.DTLSInfo) {

}

func (d *DTLSConnection) GetLocalDTLS() *sdp.DTLSInfo {

	return nil
}

func (d *DTLSConnection) Start() (err error) {

	var dtlsConn *dtls.Conn

	dtlsConfig := &dtls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{d.x509Cert.Raw},
				PrivateKey:  d.privateKey,
			},
		},
		SRTPProtectionProfiles: []dtls.SRTPProtectionProfile{dtls.SRTP_AES128_CM_HMAC_SHA1_80},
		ClientAuth:             dtls.RequireAnyClientCert,
		InsecureSkipVerify:     true,
	}

	// todo
	isClient := true

	if isClient {
		dtlsConn, err = dtls.Client(d.entpoint, dtlsConfig)
	} else {
		dtlsConn, err = dtls.Server(d.entpoint, dtlsConfig)
	}

	d.conn = dtlsConn
	return
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
	i, err := d.entpoint.inbuffer.Write(data)
	return i, err
}

func (d *DTLSConnection) Read(data []byte) (int, error) {
	i, err := d.entpoint.outbuffer.Read(data)
	return i, err
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
