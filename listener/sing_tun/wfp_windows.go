//go:build windows && with_gvisor && (amd64 || 386)

package sing_tun

import (
	"context"
	"fmt"
	"time"

	"github.com/metacubex/mihomo/component/windivert"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	tun "github.com/metacubex/sing-tun"
	"golang.org/x/exp/slices"
)

func (l *Listener) startWFP() error {
	options := l.options
	if options.Stack != C.TunGvisor {
		return fmt.Errorf("wfp requires stack: gvisor")
	}
	if options.GSO || options.FileDescriptor != 0 || options.AutoRedirect || options.StrictRoute ||
		len(options.LoopbackAddress) > 0 || len(options.RouteAddressSet) > 0 || len(options.RouteExcludeAddressSet) > 0 ||
		len(options.ExcludeSrcPortRange) > 0 || len(options.ExcludeDstPortRange) > 0 {
		return fmt.Errorf("wfp does not support gso, file-descriptor, auto-redirect, strict-route, loopback-address, route address sets or port ranges")
	}
	mtu := options.MTU
	if mtu == 0 {
		mtu = 1500
	}
	if mtu < 1280 || mtu > 65535 {
		return fmt.Errorf("wfp mtu must be between 1280 and 65535")
	}
	routes := append(slices.Clone(options.RouteAddress), options.Inet4RouteAddress...)
	excludes := append(slices.Clone(options.RouteExcludeAddress), options.Inet4RouteExcludeAddress...)
	device, err := windivert.New(windivert.Options{
		MTU: mtu, IPv6: len(options.Inet6Address) > 0,
		HijackDNS:        l.handler.ShouldHijackDns,
		RouteAddress:     append(routes, options.Inet6RouteAddress...),
		ExcludeAddress:   append(excludes, options.Inet6RouteExcludeAddress...),
		IncludeInterface: options.IncludeInterface, ExcludeInterface: options.ExcludeInterface,
		ExcludeSrcPort: options.ExcludeSrcPort, ExcludeDstPort: options.ExcludeDstPort,
	})
	if err != nil {
		return err
	}
	l.tunIf = device
	udpTimeout := time.Duration(options.UDPTimeout) * time.Second
	if udpTimeout <= 0 {
		udpTimeout = C.DefaultUDPTimeout
	}
	err = l.startStack(tun.StackOptions{
		Context: context.Background(), Tun: device, TunOptions: tun.Options{MTU: mtu},
		UDPTimeout: udpTimeout, Handler: l.handler, Logger: log.SingLogger,
	})
	if err != nil {
		return err
	}
	if err = device.Start(); err != nil {
		return err
	}
	l.tunName = "WinDivert"
	l.addrStr = fmt.Sprintf("WinDivert(WFP), mtu: %d, ip stack: gVisor", mtu)
	return nil
}
