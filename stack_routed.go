//go:build with_gvisor

package tun

import (
	"context"
	"net/netip"
	"time"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
	"github.com/sagernet/gvisor/pkg/waiter"
	"github.com/sagernet/sing-tun/internal/clashtcpip"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/canceler"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

type Routed struct {
	ctx    context.Context
	mtu    int
	logger logger.Logger

	tun       Tun
	routeTuns []RouteTun

	// gvisor stack
	stack                  *stack.Stack
	endpoint               *channel.Endpoint
	handler                Handler
	udpTimeout             int64
	endpointIndependentNat bool
}

func NewRouted(
	options StackOptions,
) (Stack, error) {
	if len(options.RoutedTuns) > 0 && !options.TunOptions.DNSAddress.IsValid() {
		return nil, E.New("dns_address is required for routed tun")
	}

	stack := &Routed{
		ctx:                    options.Context,
		mtu:                    int(options.TunOptions.MTU),
		logger:                 options.Logger,
		tun:                    options.Tun,
		routeTuns:              options.RoutedTuns,
		handler:                options.Handler,
		udpTimeout:             options.UDPTimeout,
		endpointIndependentNat: options.EndpointIndependentNat,
	}

	return stack, nil
}

func (s *Routed) Start() error {
	// Init gvisor stack
	endpoint := channel.New(1024, uint32(s.mtu), "")
	ipStack, err := newGVisorStack(endpoint)
	if err != nil {
		return err
	}

	tcpForwarder := tcp.NewForwarder(ipStack, 0, 1024, func(r *tcp.ForwarderRequest) {
		var wq waiter.Queue
		handshakeCtx, cancel := context.WithCancel(context.Background())
		go func() {
			select {
			case <-s.ctx.Done():
				wq.Notify(wq.Events())
			case <-handshakeCtx.Done():
			}
		}()
		endpoint, err := r.CreateEndpoint(&wq)
		cancel()
		if err != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)
		endpoint.SocketOptions().SetKeepAlive(true)
		keepAliveIdle := tcpip.KeepaliveIdleOption(15 * time.Second)
		endpoint.SetSockOpt(&keepAliveIdle)
		keepAliveInterval := tcpip.KeepaliveIntervalOption(15 * time.Second)
		endpoint.SetSockOpt(&keepAliveInterval)
		tcpConn := gonet.NewTCPConn(&wq, endpoint)
		lAddr := tcpConn.RemoteAddr()
		rAddr := tcpConn.LocalAddr()
		if lAddr == nil || rAddr == nil {
			tcpConn.Close()
			return
		}
		go func() {
			var metadata M.Metadata
			metadata.Source = M.SocksaddrFromNet(lAddr)
			metadata.Destination = M.SocksaddrFromNet(rAddr)
			hErr := s.handler.NewConnection(s.ctx, &gTCPConn{tcpConn}, metadata)
			if hErr != nil {
				endpoint.Abort()
			}
		}()
	})
	ipStack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	if !s.endpointIndependentNat {
		udpForwarder := udp.NewForwarder(ipStack, func(request *udp.ForwarderRequest) {
			var wq waiter.Queue
			endpoint, err := request.CreateEndpoint(&wq)
			if err != nil {
				return
			}
			udpConn := gonet.NewUDPConn(ipStack, &wq, endpoint)
			lAddr := udpConn.RemoteAddr()
			rAddr := udpConn.LocalAddr()
			if lAddr == nil || rAddr == nil {
				endpoint.Abort()
				return
			}
			gConn := &gUDPConn{UDPConn: udpConn}
			go func() {
				var metadata M.Metadata
				metadata.Source = M.SocksaddrFromNet(lAddr)
				metadata.Destination = M.SocksaddrFromNet(rAddr)
				ctx, conn := canceler.NewPacketConn(s.ctx, bufio.NewUnbindPacketConnWithAddr(gConn, metadata.Destination), time.Duration(s.udpTimeout)*time.Second)
				hErr := s.handler.NewPacketConnection(ctx, conn, metadata)
				if hErr != nil {
					endpoint.Abort()
				}
			}()
		})
		ipStack.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
	} else {
		ipStack.SetTransportProtocolHandler(udp.ProtocolNumber, NewUDPForwarder(s.ctx, ipStack, s.handler, s.udpTimeout).HandlePacket)
	}
	s.stack = ipStack
	s.endpoint = endpoint

	go s.inboundLoop()
	for _, tun := range s.routeTuns {
		go s.outboundLoop(tun)
	}
	go s.gvisorOutboundLoop()

	return nil
}

func (s *Routed) Close() error {
	for _, tun := range s.routeTuns {
		err := tun.Close()
		if err != nil {
			return err
		}
	}

	s.endpoint.Attach(nil)
	s.stack.Close()
	for _, endpoint := range s.stack.CleanupEndpoints() {
		endpoint.Abort()
	}

	return nil
}

func (s *Routed) inboundLoop() {
	packetBuffer := make([]byte, s.mtu+PacketOffset)
	for {
		n, err := s.tun.Read(packetBuffer)
		if err != nil {
			if E.IsClosed(err) {
				return
			}
			s.logger.Error(E.Cause(err, "read packet"))
		}
		if n < clashtcpip.IPv4PacketMinLength {
			continue
		}
		rawPacket := packetBuffer[:n]
		err = s.processPacket(rawPacket)
		if err != nil {
			s.logger.Trace(err)
		}
	}
}

func destFromPacket(rawPacket []byte) (netip.Addr, error) {
	switch ipVersion := rawPacket[PacketOffset] >> 4; ipVersion {
	case 4:
		return clashtcpip.IPv4Packet(rawPacket).DestinationIP(), nil
	case 6:
		return clashtcpip.IPv6Packet(rawPacket).DestinationIP(), nil
	default:
		return netip.Addr{}, E.New("ip: unknown version: ", ipVersion)
	}
}

func (s *Routed) processPacket(rawPacket []byte) (err error) {
	dest, err := destFromPacket(rawPacket)
	if err != nil {
		return err
	}

	for _, tun := range s.routeTuns {
		if tun.Contains(dest) {
			_, err = tun.Write(rawPacket)
			return
		}
	}

	// Fallback to default stack
	packet := rawPacket[PacketOffset:]
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload:           buffer.MakeWithData(packet),
		IsForwardedPacket: true,
	})
	var protocol tcpip.NetworkProtocolNumber
	switch ipVersion := rawPacket[PacketOffset] >> 4; ipVersion {
	case 4:
		protocol = header.IPv4ProtocolNumber
	case 6:
		protocol = header.IPv6ProtocolNumber
	default:
		return E.New("ip: unknown version: ", ipVersion)
	}
	s.endpoint.InjectInbound(protocol, pkt)
	pkt.DecRef()

	return
}

func (s *Routed) gvisorOutboundLoop() {
	for {
		packet := s.endpoint.ReadContext(s.ctx)
		if packet == nil {
			break
		}
		bufio.WriteVectorised(s.tun, packet.AsSlices())
		packet.DecRef()
	}
}

func (s *Routed) outboundLoop(tun RouteTun) {
	packetBuffer := make([]byte, s.mtu+PacketOffset)
	for {
		n, err := tun.Read(packetBuffer)
		if err != nil {
			if E.IsClosed(err) {
				return
			}

			s.logger.Error(E.Cause(err, "read packet"))
		}

		if n < clashtcpip.IPv4PacketMinLength {
			continue
		}

		packet := packetBuffer[:n]
		_, err = s.tun.Write(packet)
		if err != nil {
			s.logger.Trace(err)
		}
	}
}
