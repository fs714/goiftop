package engine

import (
	"errors"
	"github.com/fs714/goiftop/accounting"
	"github.com/fs714/goiftop/decoder"
	"github.com/fs714/goiftop/utils/log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"strings"
)

func NewLibPcapEngine(ifaceName, bpfFilter string, direction pcap.Direction, snaplen int32, isDecodeL4 bool) (engine *LibPcapEngine) {
	engine = &LibPcapEngine{
		IfaceName:            ifaceName,
		BpfFilter:            bpfFilter,
		Direction:            direction,
		SnapLen:              snaplen,
		IsDecodeL4:           isDecodeL4,
		FlowCol:              accounting.NewFlowCollection(ifaceName),
		FlowColResetInterval: DefaultFlowColResetInterval,
	}

	return
}

type LibPcapEngine struct {
	IfaceName            string
	BpfFilter            string
	Direction            pcap.Direction
	SnapLen              int32
	IsDecodeL4           bool
	FlowCol              *accounting.FlowCollection
	FlowColResetInterval int64
}

func (e *LibPcapEngine) StartInform(accd *accounting.Accounting) {
	Inform(accd, e.FlowCol, e.FlowColResetInterval)
}

func (e *LibPcapEngine) StartCapture() (err error) {
	handle, err := pcap.OpenLive(e.IfaceName, e.SnapLen, true, pcap.BlockForever)
	if err != nil {
		log.Errorf("failed to open live interface %s by LibPcapEngine with err: %s", e.IfaceName, err.Error())
		return
	}

	err = handle.SetBPFFilter(e.BpfFilter)
	if err != nil {
		log.Errorf("failed to set BPF filter %s by LibPcapEngine with err: %s", e.BpfFilter, err.Error())
		return
	}

	err = handle.SetDirection(e.Direction)
	if err != nil {
		log.Errorf("failed to set direction by LibPcapEngine with err: %s", err.Error())
		return
	}

	defer handle.Close()

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

	firstLayer := dec.GetFirstLayerType(handle.LinkType())
	if firstLayer == gopacket.LayerTypeZero {
		err = errors.New("failed to find first decode layer type")
		log.Errorln(err.Error())
		return
	}

	decoded := make([]gopacket.LayerType, 0, 8)
	data := make([]byte, e.SnapLen)
	fingerprint := &accounting.FlowFingerprint{}
	l3Bytes := new(int64)
	l4Bytes := new(int64)
	for {
		data, _, err = handle.ZeroCopyReadPacketData()
		if err != nil {
			log.Errorf("error getting packet: %s", err.Error())
			continue
		}

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
	}
}

func (e *LibPcapEngine) StartEngine(accd *accounting.Accounting) (err error) {
	go e.StartInform(accd)
	err = e.StartCapture()

	return
}
