package engine

import (
	"github.com/fs714/goiftop/accounting"
	"github.com/fs714/goiftop/decoder"
	"github.com/fs714/goiftop/utils/log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"strings"
	"time"
)

const LibPcapEngineName = "libpcap"
const AfpacketEngineName = "afpacket"
const NflogEngineName = "nflog"
const DefaultFlowColResetInterval = 1
const DefaultPacketDataChannelSize = 64

type PktCapEngine interface {
	StartEngine(*accounting.Accounting) error
	GetDirection() pcap.Direction
	GetFlowCollection() *accounting.FlowCollection
	GetResetInterval() int64
	GetIsDecodeL4() bool
	GetNotifyChannel() chan accounting.FlowCollection
}

func Notify(engine PktCapEngine) {
	flowCol := engine.GetFlowCollection()
	direction := engine.GetDirection()
	resetInterval := engine.GetResetInterval()
	notifyChannel := engine.GetNotifyChannel()
	now := time.Now().Unix()
	flowCol.SetTimestamp(now-resetInterval, now)

	if direction == pcap.DirectionOut {
		for _, f := range flowCol.L3FlowMap {
			f.OutboundDuration = resetInterval
		}
		for _, f := range flowCol.L4FlowMap {
			f.OutboundDuration = resetInterval
		}
	} else {
		for _, f := range flowCol.L3FlowMap {
			f.InboundDuration = resetInterval
		}
		for _, f := range flowCol.L4FlowMap {
			f.InboundDuration = resetInterval
		}
	}

	notifyChannel <- *flowCol.Copy()
	flowCol.Reset()
}

type CaptureLayers struct {
	eth      *layers.Ethernet
	linuxSll *layers.LinuxSLL
	dot1q    *layers.Dot1Q
	ipv4     *layers.IPv4
	tcp      *layers.TCP
	udp      *layers.UDP
	dns      *layers.DNS
	icmpv4   *layers.ICMPv4
	gre      *layers.GRE
	llc      *layers.LLC
	arp      *layers.ARP
	payload  *gopacket.Payload
}

type Capture struct {
	CaptureLayers
	IsDecodeL4 bool
	Direction  pcap.Direction
	FlowCol    *accounting.FlowCollection

	DecodingLayerList []gopacket.DecodingLayer
	Dec               *decoder.LayerDecoder
	Decoded           []gopacket.LayerType
	FirstLayer        gopacket.LayerType

	L3Fingerprint *accounting.FlowFingerprint
	L4Fingerprint *accounting.FlowFingerprint
	L3Bytes       *int64
	L4Bytes       *int64
}

func NewCapture(engine PktCapEngine) (capture *Capture) {
	capture = &Capture{}
	capture.eth = &layers.Ethernet{}
	capture.linuxSll = &layers.LinuxSLL{}
	capture.dot1q = &layers.Dot1Q{}
	capture.ipv4 = &layers.IPv4{}
	capture.tcp = &layers.TCP{}
	capture.udp = &layers.UDP{}
	capture.dns = &layers.DNS{}
	capture.icmpv4 = &layers.ICMPv4{}
	capture.gre = &layers.GRE{}
	capture.llc = &layers.LLC{}
	capture.arp = &layers.ARP{}
	capture.payload = &gopacket.Payload{}

	capture.IsDecodeL4 = engine.GetIsDecodeL4()
	capture.Direction = engine.GetDirection()
	capture.FlowCol = engine.GetFlowCollection()

	if capture.IsDecodeL4 {
		capture.DecodingLayerList = []gopacket.DecodingLayer{
			capture.eth,
			capture.linuxSll,
			capture.dot1q,
			capture.ipv4,
			capture.tcp,
			capture.udp,
			capture.dns,
			capture.icmpv4,
			capture.gre,
			capture.llc,
			capture.arp,
			capture.payload,
		}
	} else {
		capture.DecodingLayerList = []gopacket.DecodingLayer{
			capture.eth,
			capture.linuxSll,
			capture.dot1q,
			capture.ipv4,
			capture.payload,
		}
	}

	capture.Dec = decoder.NewLayerDecoder(capture.DecodingLayerList...)
	capture.Decoded = make([]gopacket.LayerType, 0, 8)

	capture.L3Fingerprint = &accounting.FlowFingerprint{}
	capture.L4Fingerprint = &accounting.FlowFingerprint{}
	capture.L3Bytes = new(int64)
	capture.L4Bytes = new(int64)

	return
}

func (c *Capture) SetFirstLayer(l gopacket.LayerType) {
	c.FirstLayer = l
}

func (c *Capture) DecodeAndAccount(data []byte) {
	err := c.Dec.DecodeLayers(data, c.FirstLayer, &c.Decoded)
	if err != nil {
		if c.IsDecodeL4 {
			ignoreErr := false
			for _, s := range []string{"IPv6", "DHCPv4", "IGMP", "TLS", "STP", "NTP", "VRRP", "SNAP", "LinkLayerDiscovery", "Fragment"} {
				if strings.Contains(err.Error(), s) {
					ignoreErr = true
					break
				}
			}
			if !ignoreErr {
				log.Errorf("error decoding packet with err: %s", err.Error())
			}
		}
	}

	if !c.IsDecodeL4 {
		for _, ly := range c.Decoded {
			switch ly {
			case layers.LayerTypeIPv4:
				if c.Direction == pcap.DirectionOut {
					c.L3Fingerprint.SrcAddr = c.ipv4.DstIP.String()
					c.L3Fingerprint.DstAddr = c.ipv4.SrcIP.String()
				} else {
					c.L3Fingerprint.SrcAddr = c.ipv4.SrcIP.String()
					c.L3Fingerprint.DstAddr = c.ipv4.DstIP.String()
				}
				*c.L3Bytes = int64(c.ipv4.Length)
				break
			}
		}

		if c.L3Fingerprint.SrcAddr != "" {
			if c.Direction == pcap.DirectionOut {
				c.FlowCol.UpdateL3Outbound(*c.L3Fingerprint, *c.L3Bytes, 1)
			} else {
				c.FlowCol.UpdateL3Inbound(*c.L3Fingerprint, *c.L3Bytes, 1)
			}
		}

		c.L3Fingerprint.SrcAddr = ""
		c.L3Fingerprint.DstAddr = ""
		*c.L3Bytes = 0
	} else {
		for _, ly := range c.Decoded {
			switch ly {
			case layers.LayerTypeIPv4:
				if c.Direction == pcap.DirectionOut {
					c.L3Fingerprint.SrcAddr = c.ipv4.DstIP.String()
					c.L3Fingerprint.DstAddr = c.ipv4.SrcIP.String()
				} else {
					c.L3Fingerprint.SrcAddr = c.ipv4.SrcIP.String()
					c.L3Fingerprint.DstAddr = c.ipv4.DstIP.String()
				}
				*c.L3Bytes = int64(c.ipv4.Length)

				c.L4Fingerprint.SrcAddr = c.L3Fingerprint.SrcAddr
				c.L4Fingerprint.DstAddr = c.L3Fingerprint.DstAddr
				break
			case layers.LayerTypeTCP:
				if c.Direction == pcap.DirectionOut {
					c.L4Fingerprint.SrcPort = uint16(c.tcp.DstPort)
					c.L4Fingerprint.DstPort = uint16(c.tcp.SrcPort)
				} else {
					c.L4Fingerprint.SrcPort = uint16(c.tcp.SrcPort)
					c.L4Fingerprint.DstPort = uint16(c.tcp.DstPort)
				}
				c.L4Fingerprint.Protocol = "tcp"
				*c.L4Bytes = int64(len(c.tcp.Contents) + len(c.tcp.LayerPayload()))
				break
			case layers.LayerTypeUDP:
				if c.Direction == pcap.DirectionOut {
					c.L4Fingerprint.SrcPort = uint16(c.udp.DstPort)
					c.L4Fingerprint.DstPort = uint16(c.udp.SrcPort)
				} else {
					c.L4Fingerprint.SrcPort = uint16(c.udp.SrcPort)
					c.L4Fingerprint.DstPort = uint16(c.udp.DstPort)
				}
				c.L4Fingerprint.Protocol = "udp"
				*c.L4Bytes = int64(c.udp.Length)
				break
			case layers.LayerTypeICMPv4:
				c.L4Fingerprint.Protocol = "icmp"
				*c.L4Bytes = int64(len(c.icmpv4.Contents) + len(c.icmpv4.LayerPayload()))
				break
			}
		}

		if c.L3Fingerprint.SrcAddr != "" {
			if c.Direction == pcap.DirectionOut {
				c.FlowCol.UpdateL3Outbound(*c.L3Fingerprint, *c.L3Bytes, 1)
			} else {
				c.FlowCol.UpdateL3Inbound(*c.L3Fingerprint, *c.L3Bytes, 1)
			}

			if c.L4Fingerprint.Protocol != "" {
				if c.Direction == pcap.DirectionOut {
					c.FlowCol.UpdateL4Outbound(*c.L4Fingerprint, *c.L4Bytes, 1)
				} else {
					c.FlowCol.UpdateL4Inbound(*c.L4Fingerprint, *c.L4Bytes, 1)
				}
			}
		}

		c.L3Fingerprint.SrcAddr = ""
		c.L3Fingerprint.DstAddr = ""
		c.L4Fingerprint.SrcAddr = ""
		c.L4Fingerprint.DstAddr = ""
		c.L4Fingerprint.SrcPort = 0
		c.L4Fingerprint.DstPort = 0
		c.L4Fingerprint.Protocol = ""
		*c.L3Bytes = 0
		*c.L4Bytes = 0
	}
}
