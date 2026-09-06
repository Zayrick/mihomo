//go:build windows && with_gvisor && (amd64 || 386)

package sing_tun

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/nat"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
)

type wfpEchoTunnel struct {
	table C.NatTable
	seen  chan *C.Metadata
}

func (e *wfpEchoTunnel) NatTable() C.NatTable { return e.table }
func (e *wfpEchoTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	defer conn.Close()
	e.seen <- metadata
	io.Copy(conn, conn)
}
func (e *wfpEchoTunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {
	defer packet.Drop()
	e.seen <- metadata
	packet.WriteBack(packet.Data(), &net.UDPAddr{IP: metadata.DstIP.AsSlice(), Port: int(metadata.DstPort)})
}

func TestWFPIntegration(t *testing.T) {
	if os.Getenv("MIHOMO_WFP_TEST") != "1" {
		t.Skip("set MIHOMO_WFP_TEST=1 as administrator to load the embedded driver")
	}
	echo := &wfpEchoTunnel{table: nat.New(), seen: make(chan *C.Metadata, 8)}
	options := LC.Tun{Driver: "wfp", Stack: C.TunGvisor, RouteAddress: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/32")}}
	networks := []string{"tcp4", "udp4"}
	if os.Getenv("MIHOMO_WFP_TEST_IPV6") == "1" {
		options.Inet6Address = []netip.Prefix{netip.MustParsePrefix("fdfe::1/126")}
		options.RouteAddress = append(options.RouteAddress, netip.MustParsePrefix("2001:db8::1/128"))
		networks = append(networks, "tcp6", "udp6")
	}
	l, err := New(options, echo)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for _, network := range networks {
		t.Run(network, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWFPClient$")
			child.Env = append(os.Environ(), "MIHOMO_WFP_CLIENT="+network)
			if output, err := child.CombinedOutput(); err != nil {
				t.Fatalf("child: %v\n%s", err, output)
			}
			select {
			case metadata := <-echo.seen:
				destination := "198.18.0.1"
				if network[len(network)-1] == '6' {
					destination = "2001:db8::1"
				}
				if metadata.DstIP.String() != destination || metadata.DstPort != 18473 {
					t.Fatalf("original destination lost: %+v", metadata)
				}
			case <-ctx.Done():
				t.Fatal("packet did not reach mihomo tunnel")
			}
		})
	}
	conn, err := net.DialTimeout("tcp4", "198.18.0.1:18473", 500*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Fatal("the listener's own connection was intercepted")
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	l, err = New(options, echo)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWFPClient(t *testing.T) {
	network := os.Getenv("MIHOMO_WFP_CLIENT")
	if network == "" {
		t.Skip("integration-test subprocess")
	}
	destination := "198.18.0.1:18473"
	if network[len(network)-1] == '6' {
		destination = "[2001:db8::1]:18473"
	}
	conn, err := net.DialTimeout(network, destination, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	repeat := 40
	if network[:3] == "tcp" {
		repeat = 1000
	}
	payload := bytes.Repeat([]byte("mihomo WFP TCP/UDP round trip"), repeat)
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply, payload) {
		t.Fatalf("incorrect reply: %q", reply)
	}
}
