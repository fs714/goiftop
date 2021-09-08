package engine

import (
	"errors"
	"fmt"
	"github.com/fs714/goiftop/decoder"
	"github.com/fs714/goiftop/utils/log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"strings"
	"time"
)

func NewLibPcapEngine(ifaceName, bpfFilter string, direction pcap.Direction, snaplen int32, isDecodeL4 bool) (engine *LibPcapEngine) {
	engine = &LibPcapEngine{
		IfaceName:  ifaceName,
		BpfFilter:  bpfFilter,
		Direction:  direction,
		SnapLen:    snaplen,
		IsDecodeL4: isDecodeL4,
	}

	return
}

type LibPcapEngine struct {
	IfaceName  string
	BpfFilter  string
	Direction  pcap.Direction
	SnapLen    int32
	IsDecodeL4 bool
}

func (e *LibPcapEngine) StartEngine() (err error) {
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
	var ipCnt, ipBytes, tcpCnt, tcpBytes, udpCnt, udpBytes, icmpCnt, icmpBytes int64
	ticker := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-ticker.C:
			ipPps := ipCnt
			ipRate := float64(ipBytes*8/1000) / 1000
			tcpPps := tcpCnt
			tcpRate := float64(tcpBytes*8/1000) / 1000
			udpPps := udpCnt
			udpRate := float64(udpBytes*8/1000) / 1000
			icmpPps := icmpCnt
			icmpRate := float64(icmpBytes*8/1000) / 1000

			fmt.Printf("IpPPS: %d, IpRate: %.2f, TcpPPS: %d, TcpRate: %.2f, UdpPPS: %d, UdpRate: %.2f, IcmpPPS: %d, IcmpRate: %.2f\n",
				ipPps, ipRate, tcpPps, tcpRate, udpPps, udpRate, icmpPps, icmpRate)

			ipCnt = 0
			ipBytes = 0
			tcpCnt = 0
			tcpBytes = 0
			udpCnt = 0
			udpBytes = 0
			icmpCnt = 0
			icmpBytes = 0
		default:
			data, _, err := handle.ZeroCopyReadPacketData()
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
					ipCnt++
					ipBytes += int64(ipv4.Length)
					break
				case layers.LayerTypeTCP:
					tcpCnt++
					tcpBytes += int64(len(tcp.Contents) + len(tcp.LayerPayload()))
					break
				case layers.LayerTypeUDP:
					udpCnt++
					udpBytes += int64(udp.Length)
					break
				case layers.LayerTypeICMPv4:
					icmpCnt++
					icmpBytes += int64(len(icmpv4.Contents) + len(icmpv4.LayerPayload()))
					break
				}
			}
		}
	}
}
