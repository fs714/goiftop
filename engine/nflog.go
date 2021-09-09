// # iptables -I OUTPUT -p icmp -j NFLOG --nflog-group 100
// # iptables -t raw -A PREROUTING -i eth1 -j NFLOG --nflog-group 2 --nflog-range 64 --nflog-threshold 10
// # iptables -t mangle -A POSTROUTING -o eth1 -j NFLOG --nflog-group 5 --nflog-range 64 --nflog-threshold 10

package engine

import (
	"github.com/fs714/goiftop/accounting"
	"github.com/fs714/goiftop/decoder"
	"github.com/fs714/goiftop/engine/nflog"
	"github.com/fs714/goiftop/utils/log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"strings"
)

func NewNflogEngine(ifaceName string, groupId int, direction pcap.Direction, isDecodeL4 bool) (engine *NflogEngine) {
	engine = &NflogEngine{
		IfaceName:            ifaceName,
		GroupId:              groupId,
		Direction:            direction,
		IsDecodeL4:           isDecodeL4,
		FlowCol:              accounting.NewFlowCollection(ifaceName),
		FlowColResetInterval: DefaultFlowColResetInterval,
	}

	return
}

type NflogEngine struct {
	IfaceName            string
	GroupId              int
	Direction            pcap.Direction
	IsDecodeL4           bool
	FlowCol              *accounting.FlowCollection
	FlowColResetInterval int64
}

func (e *NflogEngine) StartInform(accd *accounting.Accounting) {
	Inform(accd, e.FlowCol, e.FlowColResetInterval)
}

func (e *NflogEngine) StartCapture() (err error) {
	var eth layers.Ethernet
	var linuxSll layers.LinuxSLL
	var dot1q layers.Dot1Q
	var ipv4 layers.IPv4
	var tcp layers.TCP
	var udp layers.UDP
	var dns layers.DNS
	var icmpv4 layers.ICMPv4
	var gre layers.GRE
	var llc layers.LLC
	var arp layers.ARP
	var payload gopacket.Payload

	var DecodingLayerList []gopacket.DecodingLayer
	if e.IsDecodeL4 {
		DecodingLayerList = []gopacket.DecodingLayer{
			&eth,
			&linuxSll,
			&dot1q,
			&ipv4,
			&tcp,
			&udp,
			&dns,
			&icmpv4,
			&gre,
			&llc,
			&arp,
			&payload,
		}
	} else {
		DecodingLayerList = []gopacket.DecodingLayer{
			&eth,
			&linuxSll,
			&dot1q,
			&ipv4,
			&payload,
		}
	}

	dec := decoder.NewLayerDecoder(DecodingLayerList...)
	firstLayer := layers.LayerTypeIPv4

	decoded := make([]gopacket.LayerType, 0, 8)
	fingerprint := &accounting.FlowFingerprint{}
	l3Bytes := new(int64)
	l4Bytes := new(int64)
	fn := func(data []byte) int {
		err = dec.DecodeLayers(data, firstLayer, &decoded)
		if err != nil {
			if e.IsDecodeL4 {
				ignoreErr := false
				for _, s := range []string{"TLS", "STP", "Fragment"} {
					if strings.Contains(err.Error(), s) {
						ignoreErr = true
					}
				}
				if !ignoreErr {
					log.Errorf("error decoding packet with err: %s", err.Error())
				}
			}
		}

		for _, ly := range decoded {
			switch ly {
			case layers.LayerTypeIPv4:
				if e.Direction == pcap.DirectionOut {
					fingerprint.SrcAddr = ipv4.DstIP.String()
					fingerprint.DstAddr = ipv4.SrcIP.String()
				} else {
					fingerprint.SrcAddr = ipv4.SrcIP.String()
					fingerprint.DstAddr = ipv4.DstIP.String()
				}
				*l3Bytes = int64(ipv4.Length)
				break
			case layers.LayerTypeTCP:
				if e.Direction == pcap.DirectionOut {
					fingerprint.SrcPort = uint16(tcp.DstPort)
					fingerprint.DstPort = uint16(tcp.SrcPort)
				} else {
					fingerprint.SrcPort = uint16(tcp.SrcPort)
					fingerprint.DstPort = uint16(tcp.DstPort)
				}
				fingerprint.Protocol = "tcp"
				*l4Bytes = int64(len(tcp.Contents) + len(tcp.LayerPayload()))
				break
			case layers.LayerTypeUDP:
				if e.Direction == pcap.DirectionOut {
					fingerprint.SrcPort = uint16(udp.DstPort)
					fingerprint.DstPort = uint16(udp.SrcPort)
				} else {
					fingerprint.SrcPort = uint16(udp.SrcPort)
					fingerprint.DstPort = uint16(udp.DstPort)
				}
				fingerprint.Protocol = "udp"
				*l4Bytes = int64(udp.Length)
				break
			case layers.LayerTypeICMPv4:
				fingerprint.Protocol = "icmp"
				*l4Bytes = int64(len(icmpv4.Contents) + len(icmpv4.LayerPayload()))
				break
			}
		}

		if fingerprint.SrcAddr != "" {
			if e.Direction == pcap.DirectionOut {
				e.FlowCol.UpdateL3Outbound(*fingerprint, *l3Bytes, 1, e.FlowColResetInterval)
			} else {
				e.FlowCol.UpdateL3Inbound(*fingerprint, *l3Bytes, 1, e.FlowColResetInterval)
			}

			if e.IsDecodeL4 && fingerprint.Protocol != "" {
				if e.Direction == pcap.DirectionOut {
					e.FlowCol.UpdateL4Outbound(*fingerprint, *l3Bytes, 1, e.FlowColResetInterval)
				} else {
					e.FlowCol.UpdateL4Inbound(*fingerprint, *l3Bytes, 1, e.FlowColResetInterval)
				}
			}
		}

		fingerprint.SrcAddr = ""
		fingerprint.DstAddr = ""
		fingerprint.SrcPort = 0
		fingerprint.DstPort = 0
		fingerprint.Protocol = ""
		*l3Bytes = 0
		*l4Bytes = 0

		return 0
	}

	nfl := nflog.NewNfLog(e.GroupId, fn)
	defer nfl.Close()

	return
}

func (e *NflogEngine) StartEngine(accd *accounting.Accounting) (err error) {
	go e.StartInform(accd)
	err = e.StartCapture()

	return
}
