//go:build windows && (amd64 || 386)

package windivert

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"testing"
	"unsafe"
)

func TestAddressLayout(t *testing.T) {
	if unsafe.Sizeof(address{}) != 80 || unsafe.Offsetof(address{}.IfIdx) != 16 {
		t.Fatal("WinDivert ABI layout mismatch")
	}
}

func TestSocketOwner(t *testing.T) {
	device := new(Tun)
	for _, network := range []string{"udp4", "udp6"} {
		conn, err := net.ListenPacket(network, ":0")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		addr := conn.LocalAddr().(*net.UDPAddr).AddrPort()
		ip := netip.MustParseAddr("127.0.0.1")
		if network == "udp6" {
			ip = netip.IPv6Loopback()
		}
		key := flow{source: netip.AddrPortFrom(ip, addr.Port()), protocol: 17}
		owners, err := device.socketTable(key)
		if err != nil || socketOwner(owners, key) != uint32(os.Getpid()) {
			t.Fatalf("%s owner=%d err=%v", network, socketOwner(owners, key), err)
		}
		conn.Close()
		owners, err = device.socketTable(key)
		if err != nil || socketOwner(owners, key) != 0 {
			t.Fatalf("%s retained closed socket: %v", network, err)
		}
	}
}

func TestSharedUDPSocket(t *testing.T) {
	for _, source := range []string{"192.0.2.1:50000", "[2001:db8::1]:50000"} {
		key := flow{source: netip.MustParseAddrPort(source), protocol: 17}
		rowSize, portOffset, pidOffset := 12, 4, 8
		if key.source.Addr().Is6() {
			rowSize, portOffset, pidOffset = 28, 20, 24
		}
		// A wildcard socket and an address-specific socket share one port.
		data := make([]byte, 4+2*rowSize)
		binary.LittleEndian.PutUint32(data, 2)
		wildcard, exact := data[4:4+rowSize], data[4+rowSize:]
		copy(exact, key.source.Addr().AsSlice())
		for _, row := range [][]byte{wildcard, exact} {
			binary.BigEndian.PutUint16(row[portOffset:], key.source.Port())
			binary.LittleEndian.PutUint32(row[pidOffset:], 7)
		}
		for _, owner := range []uint32{7, 8} {
			binary.LittleEndian.PutUint32(exact[pidOffset:], owner)
			owners := parseSocketTable(data, key, nil)
			want := uint32(7)
			if owner != 7 {
				want = 0
			}
			if got := socketOwner(owners, key); got != want {
				t.Fatalf("%s owner=%d: got %d, want %d", source, owner, got, want)
			}
		}
	}
}

func TestNetworkFilterInstructions(t *testing.T) {
	n := uint16(len(networkFilter))
	for i, ins := range networkFilter {
		succ := uint16(ins.FieldTestSuccess >> 16)
		fail := uint16(ins.Failure)
		field := ins.FieldTestSuccess & 0x7ff
		for _, target := range []uint16{succ, fail} {
			if target != accept && target != reject {
				if target <= uint16(i) || target >= n {
					t.Fatalf("instruction %d invalid jump target: %d (len=%d)", i, target, n)
				}
			}
		}
		// Validate against WinDivert driver windivert_filter_compile constraints.
		switch field {
		case fieldIPDstAddr:
			if ins.Arg[1] != 0x0000ffff {
				t.Fatalf("instruction %d field %d requires Arg[1]==0x0000ffff for IPv4 mapping, got %x", i, field, ins.Arg[1])
			}
		case fieldUDPSrcPort, fieldUDPDstPort:
			if ins.Arg[0] > 0xffff || ins.Arg[1] != 0 {
				t.Fatalf("instruction %d port out of range: %v", i, ins.Arg)
			}
		}
	}

	eval := func(fields map[uint32]uint32) uint16 {
		ip := uint16(0)
		for {
			ins := networkFilter[ip]
			field := ins.FieldTestSuccess & 0x7ff
			succ := uint16(ins.FieldTestSuccess >> 16)
			fail := uint16(ins.Failure)
			val, present := fields[field]
			if present && val == ins.Arg[0] {
				if succ == accept || succ == reject {
					return succ
				}
				ip = succ
			} else {
				if fail == accept || fail == reject {
					return fail
				}
				ip = fail
			}
		}
	}

	tests := []struct {
		name   string
		fields map[uint32]uint32
		want   uint16
	}{
		{
			name:   "inbound",
			fields: map[uint32]uint32{fieldOutbound: 0},
			want:   reject,
		},
		{
			name:   "loopback",
			fields: map[uint32]uint32{fieldOutbound: 1, fieldLoopback: 1},
			want:   reject,
		},
		{
			name:   "impostor",
			fields: map[uint32]uint32{fieldOutbound: 1, fieldLoopback: 0, fieldImpostor: 1},
			want:   reject,
		},
		{
			name:   "outbound TCP",
			fields: map[uint32]uint32{fieldOutbound: 1, fieldLoopback: 0, fieldImpostor: 0, fieldTCP: 1},
			want:   accept,
		},
		{
			name: "outbound unicast UDP",
			fields: map[uint32]uint32{
				fieldOutbound: 1, fieldLoopback: 0, fieldImpostor: 0,
				fieldUDP: 1, fieldUDPSrcPort: 50000, fieldUDPDstPort: 53,
				fieldIPDstAddr: 0x08080808,
			},
			want: accept,
		},
		{
			name: "DHCPv4 client discover",
			fields: map[uint32]uint32{
				fieldOutbound: 1, fieldLoopback: 0, fieldImpostor: 0,
				fieldUDP: 1, fieldUDPSrcPort: 68, fieldUDPDstPort: 67,
				fieldIPDstAddr: 0xffffffff,
			},
			want: reject,
		},
		{
			name: "DHCPv4 server reply",
			fields: map[uint32]uint32{
				fieldOutbound: 1, fieldLoopback: 0, fieldImpostor: 0,
				fieldUDP: 1, fieldUDPSrcPort: 67, fieldUDPDstPort: 68,
			},
			want: reject,
		},
		{
			name: "DHCPv6 client solicit",
			fields: map[uint32]uint32{
				fieldOutbound: 1, fieldLoopback: 0, fieldImpostor: 0,
				fieldUDP: 1, fieldUDPSrcPort: 546, fieldUDPDstPort: 547,
			},
			want: reject,
		},
		{
			name: "limited broadcast UDP",
			fields: map[uint32]uint32{
				fieldOutbound: 1, fieldLoopback: 0, fieldImpostor: 0,
				fieldUDP: 1, fieldUDPSrcPort: 12345, fieldUDPDstPort: 12345,
				fieldIPDstAddr: 0xffffffff,
			},
			want: reject,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := eval(tc.fields); got != tc.want {
				t.Fatalf("eval() = %x, want %x", got, tc.want)
			}
		})
	}
}

