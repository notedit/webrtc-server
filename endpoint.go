package webrtc

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/notedit/sdp"
	"github.com/notedit/webrtc-server/packet"
	"github.com/pion/stun"
)

type Endpoint struct {
	ip           string
	port         int
	udpConn      *net.UDPConn
	readPackets  chan *packet.UDP
	writePackets chan *packet.UDP
	candidate    *sdp.CandidateInfo
	running      bool

	connections      map[string]*Transport
	remoteCandidates map[*net.UDPAddr]*Transport

	sync.RWMutex
}

func NewEndpoint(ctx context.Context, ip string, port int) (*Endpoint, error) {

	var udpConn *net.UDPConn
	var err error

	udpConn, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: port})

	if err != nil {
		return nil, err
	}

	endpoint := &Endpoint{}
	endpoint.ip = ip
	endpoint.port = port
	endpoint.udpConn = udpConn
	endpoint.readPackets = make(chan *packet.UDP, 1024)
	endpoint.writePackets = make(chan *packet.UDP, 1024)
	endpoint.candidate = sdp.NewCandidateInfo("1", 1, "UDP", 33554431, ip, port, "host", "", 0)
	endpoint.connections = make(map[string]*Transport)
	endpoint.remoteCandidates = make(map[*net.UDPAddr]*Transport)

	go endpoint.readLoop(ctx)
	go endpoint.writeLoop(ctx)

	return endpoint, nil
}

func (e *Endpoint) readLoop(ctx context.Context) {

	var totalReceivedSize uint64
	e.running = true

	for e.running {

		packet := packet.NewUDP()
		size, rAddr, err := e.udpConn.ReadFromUDP(packet.GetData())

		if err != nil {
			fmt.Println(err)
			return
		}

		packet.SetCreatedAt(time.Now())
		packet.SetRAddr(rAddr)
		packet.Slice(0, size)

		atomic.AddUint64(&totalReceivedSize, uint64(size))

		select {
		case e.readPackets <- packet:
		default:
			fmt.Println("packets is full, drop packet")
		}
	}
}

func (e *Endpoint) writeLoop(ctx context.Context) {

	for {

		select {
		case <-ctx.Done():
			return
		case packet := <-e.writePackets:
			e.udpConn.WriteToUDP(packet.GetData(), packet.GetRAddr())
		}

	}
}

func (e *Endpoint) handleLoop(ctx context.Context) {

	for {
		select {
		case <-ctx.Done():
			return
		case packet := <-e.readPackets:
			e.handlePacket(packet)
		}
	}
}

func (e *Endpoint) handlePacket(packet *packet.UDP) {

	addr := packet.GetRAddr()
	var transport *Transport

	if packet.IsSTUN() {

		message := stun.New()
		err := stun.Decode(packet.GetData(), message)

		if err != nil {
			fmt.Println(err)
		}

		stunType := message.Type.Class
		stunMethod := message.Type.Method

		fmt.Println(stunType, stunMethod)

		if stunType == stun.ClassRequest && stunMethod == stun.MethodBinding {

			attr, ok := message.Attributes.Get(stun.AttrUsername)

			if !ok {
				log.Println("STUN Message without username attribute")
				return
			}

			username := string(attr.Value)

			e.RLock()
			transport = e.connections[username]
			e.RUnlock()

			if transport == nil {
				return
			}

			//Authenticate request with remote username
			//Check if it has the prio attribute
			//priority, _ := message.Attributes.Get(stun.AttrPriority)

			e.Lock()
			if _, ok := e.remoteCandidates[addr]; !ok {
				e.remoteCandidates[addr] = transport
			}
			e.Unlock()

		}

	}

	e.RLock()
	transport = e.remoteCandidates[addr]
	e.RUnlock()

	if transport == nil {
		return
	}

}
