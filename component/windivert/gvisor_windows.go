//go:build windows && with_gvisor && (amd64 || 386)

package windivert

import (
	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
	"github.com/metacubex/mihomo/log"
	tun "github.com/metacubex/sing-tun"
)

func (t *Tun) startGVisor() error {
	endpoint := channel.New(256, t.options.MTU, "")
	// Captured packets may still contain hardware-offloaded checksums.
	endpoint.LinkEPCapabilities = stack.CapabilityRXChecksumOffload
	ipStack, err := tun.NewGVisorStack(endpoint)
	if err != nil {
		endpoint.Close()
		return err
	}
	if t.options.Stack == "gvisor" {
		ipStack.SetTransportProtocolHandler(tcp.ProtocolNumber, tun.NewTCPForwarder(t.ctx, ipStack, t.options.Handler).HandlePacket)
	}
	ipStack.SetTransportProtocolHandler(udp.ProtocolNumber, tun.NewUDPForwarder(t.ctx, ipStack, t.options.Handler).HandlePacket)
	t.deliver = func(p []byte, info packetInfo) {
		protocol := header.IPv4ProtocolNumber
		if info.source.Addr().Is6() {
			protocol = header.IPv6ProtocolNumber
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(append([]byte(nil), p...)), IsForwardedPacket: true,
		})
		endpoint.InjectInbound(protocol, pkt)
		pkt.DecRef()
	}
	t.closeStack = func() {
		endpoint.Close()
		endpoint.Attach(nil)
		ipStack.Close()
		for _, endpoint := range ipStack.CleanupEndpoints() {
			endpoint.Abort()
		}
	}
	t.running.Add(1)
	go func() {
		defer t.running.Done()
		for {
			pkt := endpoint.ReadContext(t.ctx)
			if pkt == nil {
				return
			}
			view := pkt.ToView()
			_, err := t.Write(view.AsSlice())
			view.Release()
			pkt.DecRef()
			if err != nil {
				log.Warnln("[WFP] send: packet dropped: %s", err)
			}
		}
	}()
	return nil
}
