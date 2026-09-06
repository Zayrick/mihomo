//go:build windows && with_gvisor && (amd64 || 386)

package sing_tun

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/fakeip"
	"github.com/metacubex/mihomo/component/nat"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	MDNS "github.com/metacubex/mihomo/dns"
	LC "github.com/metacubex/mihomo/listener/config"
	D "github.com/miekg/dns"
)

func TestWFPDNSIntegration(t *testing.T) {
	if os.Getenv("MIHOMO_WFP_TEST") != "1" {
		t.Skip("requires administrator and MIHOMO_WFP_TEST=1")
	}
	pool, err := fakeip.New(fakeip.Options{IPNet: netip.MustParsePrefix("198.18.0.1/16"), Size: 256})
	if err != nil {
		t.Fatal(err)
	}
	previous := resolver.DefaultService
	resolver.DefaultService = MDNS.NewService(MDNS.NewResolver(MDNS.Config{}), MDNS.NewEnhancer(MDNS.EnhancerConfig{
		EnhancedMode: C.DNSFakeIP, FakeIPPool: pool, FakeIPSkipper: &fakeip.Skipper{}, FakeIPTTL: 1,
	}))
	defer func() { resolver.DefaultService = previous }()
	options := LC.Tun{Driver: "wfp", Stack: C.TunGvisor, DNSHijack: []string{"any:53"},
		RouteAddress: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/32"), netip.MustParsePrefix("2001:db8::1/128")},
	}
	modes := []string{"udp4", "tcp4"}
	if os.Getenv("MIHOMO_WFP_TEST_IPV6") == "1" {
		modes = append(modes, "udp6", "tcp6")
	}
	l, err := New(options, &wfpEchoTunnel{table: nat.New(), seen: make(chan *C.Metadata, 8)})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWFPDNSClient$")
			child.Env = append(os.Environ(), "MIHOMO_WFP_DNS_CLIENT="+mode)
			if output, err := child.CombinedOutput(); err != nil {
				t.Fatalf("DNS client: %v\n%s", err, output)
			}
		})
	}
}

func TestWFPDNSClient(t *testing.T) {
	mode := os.Getenv("MIHOMO_WFP_DNS_CLIENT")
	if mode == "" {
		t.Skip("DNS integration subprocess")
	}
	destination := "198.18.0.1:53"
	if strings.HasSuffix(mode, "6") {
		destination = "[2001:db8::1]:53"
	}
	query := new(D.Msg)
	query.SetQuestion("wfp.example.com.", D.TypeA)
	client := &D.Client{Net: mode, Timeout: 5 * time.Second}
	reply, _, err := client.Exchange(query, destination)
	if err != nil {
		t.Fatal(err)
	}
	for _, answer := range reply.Answer {
		if a, ok := answer.(*D.A); ok {
			ip, _ := netip.AddrFromSlice(a.A)
			if netip.MustParsePrefix("198.18.0.0/16").Contains(ip.Unmap()) {
				return
			}
		}
	}
	t.Fatalf("expected a fake-IP answer, got %v", reply.Answer)
}
