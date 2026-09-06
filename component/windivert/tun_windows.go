//go:build windows && with_gvisor && (amd64 || 386)

package windivert

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/mihomo/log"
	tun "github.com/metacubex/sing-tun"
	"golang.org/x/exp/slices"
)

type Options struct {
	MTU              uint32
	IPv6             bool
	HijackDNS        func(netip.AddrPort) bool
	RouteAddress     []netip.Prefix
	ExcludeAddress   []netip.Prefix
	IncludeInterface []string
	ExcludeInterface []string
	ExcludeSrcPort   []uint16
	ExcludeDstPort   []uint16
}

type Tun struct {
	handle      *handle
	endpoint    *channel.Endpoint
	options     Options
	pid         uint32
	includeIf   map[uint32]bool
	excludeIf   map[uint32]bool
	interfaceMu sync.Mutex
	tcpFlows    map[flow]uint32
	interfaces  map[netip.Addr]address
	closeOnce   sync.Once
	running     sync.WaitGroup
}

var _ tun.GVisorTun = (*Tun)(nil)

var active atomic.Bool

func New(options Options) (_ *Tun, err error) {
	if !active.CompareAndSwap(false, true) {
		return nil, fmt.Errorf("only one WFP listener can be active")
	}
	defer func() {
		if err != nil {
			active.Store(false)
		}
	}()
	t := &Tun{
		options: options, pid: uint32(os.Getpid()),
		tcpFlows: make(map[flow]uint32), interfaces: make(map[netip.Addr]address),
		includeIf: make(map[uint32]bool), excludeIf: make(map[uint32]bool),
	}
	for _, entry := range []struct {
		names   []string
		indexes map[uint32]bool
	}{
		{options.IncludeInterface, t.includeIf}, {options.ExcludeInterface, t.excludeIf},
	} {
		for _, name := range entry.names {
			iface, err := net.InterfaceByName(name)
			if err != nil {
				return nil, err
			}
			entry.indexes[uint32(iface.Index)] = true
		}
	}
	t.handle, err = openHandle()
	if err != nil {
		return nil, err
	}
	t.endpoint = channel.New(256, options.MTU, "")
	// Captured packets may still contain hardware-offloaded checksums.
	t.endpoint.LinkEPCapabilities = stack.CapabilityRXChecksumOffload
	return t, nil
}

// Start is called only after the protocol stack is ready to consume packets.
func (t *Tun) Start() error {
	if err := t.handle.start(); err != nil {
		return err
	}
	t.running.Add(2)
	go t.readLoop()
	go t.writeLoop()
	return nil
}

func (t *Tun) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	return t.endpoint, stack.NICOptions{}, nil
}

func (t *Tun) Read([]byte) (int, error) { return 0, os.ErrInvalid }

func (t *Tun) Write(p []byte) (int, error) {
	// Responses can include ICMP errors or IP fragments emitted by the stack.
	var destination netip.Addr
	if len(p) >= 20 && p[0]>>4 == 4 {
		destination, _ = netip.AddrFromSlice(p[16:20])
	} else if len(p) >= 40 && p[0]>>4 == 6 {
		destination, _ = netip.AddrFromSlice(p[24:40])
	} else {
		return 0, fmt.Errorf("invalid WFP response packet")
	}
	t.interfaceMu.Lock()
	addr, ok := t.interfaces[destination]
	t.interfaceMu.Unlock()
	if !ok {
		return 0, fmt.Errorf("WFP response interface not found for %s", destination)
	}
	return t.handle.send(p, &addr)
}

func (t *Tun) WritePacket(pkt *stack.PacketBuffer) (int, error) {
	view := pkt.ToView()
	defer view.Release()
	return t.Write(view.AsSlice())
}

func (t *Tun) selected(info packetInfo, addr address) bool {
	dst := info.destination.Addr()
	if !dst.IsGlobalUnicast() || t.excludeIf[addr.IfIdx] || (len(t.includeIf) > 0 && !t.includeIf[addr.IfIdx]) {
		return false
	}
	// DNS transport can use IPv6 even when IPv6 proxy traffic is disabled.
	if !t.options.IPv6 && dst.Is6() && (t.options.HijackDNS == nil || !t.options.HijackDNS(info.destination)) {
		return false
	}
	if len(t.options.RouteAddress) > 0 && !containsAddress(t.options.RouteAddress, dst) {
		return false
	}
	if containsAddress(t.options.ExcludeAddress, dst) {
		return false
	}
	return !slices.Contains(t.options.ExcludeSrcPort, info.source.Port()) &&
		!slices.Contains(t.options.ExcludeDstPort, info.destination.Port())
}

func containsAddress(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (t *Tun) capture(info packetInfo) bool {
	if info.protocol == 6 && info.tcpFlags&0x12 != 0x02 {
		_, captured := t.tcpFlows[info.flow]
		if info.tcpFlags&0x04 != 0 {
			delete(t.tcpFlows, info.flow)
		}
		return captured
	}
	// Resolve SYNs and UDP packets against current ownership to handle port reuse.
	entries, err := socketTable(info.flow)
	owner := entries[info.flow]
	capture := err == nil && owner != 0 && owner != t.pid
	if info.protocol == 6 {
		// Reclaim flows that have closed or changed owners.
		if err == nil {
			for key, previous := range t.tcpFlows {
				if key.source.Addr().Is6() == info.source.Addr().Is6() && entries[key] != previous {
					delete(t.tcpFlows, key)
				}
			}
		}
		if capture {
			t.tcpFlows[info.flow] = owner
		} else {
			delete(t.tcpFlows, info.flow)
		}
	}
	return capture
}

func (t *Tun) readLoop() {
	defer t.running.Done()
	p := make([]byte, 65575)
	for {
		var addr address
		n, err := t.handle.recv(p, &addr)
		if err != nil {
			t.close(fmt.Errorf("receive: %w", err))
			return
		}
		info, ok := parsePacket(p[:n])
		if !ok || !t.selected(info, addr) || !t.capture(info) {
			if _, err = t.handle.send(p[:n], &addr); err != nil {
				t.close(fmt.Errorf("bypass: %w", err))
				return
			}
			continue
		}
		t.interfaceMu.Lock()
		// Replies are inbound on this interface; zero checksum flags request recalculation.
		t.interfaces[info.source.Addr()] = address{IfIdx: addr.IfIdx, SubIfIdx: addr.SubIfIdx}
		t.interfaceMu.Unlock()
		protocol := header.IPv4ProtocolNumber
		if info.source.Addr().Is6() {
			protocol = header.IPv6ProtocolNumber
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(append([]byte(nil), p[:n]...)), IsForwardedPacket: true,
		})
		t.endpoint.InjectInbound(protocol, pkt)
		pkt.DecRef()
	}
}

func (t *Tun) writeLoop() {
	defer t.running.Done()
	for {
		pkt := t.endpoint.ReadContext(context.Background())
		if pkt == nil {
			return
		}
		_, err := t.WritePacket(pkt)
		pkt.DecRef()
		if err != nil {
			t.close(fmt.Errorf("send: %w", err))
			return
		}
	}
}

func (t *Tun) close(err error) {
	t.closeOnce.Do(func() {
		if err != nil {
			log.Errorln("[WFP] %s", err)
		}
		t.handle.close()
		t.endpoint.Close()
		active.Store(false)
	})
}

func (t *Tun) Close() error {
	t.close(nil)
	t.running.Wait()
	return nil
}
