package engine

import (
	"fmt"
	"github.com/fs714/goiftop/decoder"
	"github.com/fs714/goiftop/engine/nflog"
	"github.com/fs714/goiftop/utils/log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"strings"
	"sync"
	"time"
)

func NewNflogEngine(groupId int, direction pcap.Direction, isDecodeL4 bool) (engine *NflogEngine) {
	engine = &NflogEngine{
		GroupId:    groupId,
		Direction:  direction,
		IsDecodeL4: isDecodeL4,
	}

	return
}

type NflogEngine struct {
	GroupId    int
	Direction  pcap.Direction
	IsDecodeL4 bool
}

func (e *NflogEngine) StartEngine() (err error) {
	// # iptables -I OUTPUT -p icmp -j NFLOG --nflog-group 100
	// # iptables -t raw -A PREROUTING -i eth1 -j NFLOG --nflog-group 2 --nflog-range 64 --nflog-threshold 10
	// # iptables -t mangle -A POSTROUTING -o eth1 -j NFLOG --nflog-group 5 --nflog-range 64 --nflog-threshold 10

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
	var ipCnt, ipBytes, tcpCnt, tcpBytes, udpCnt, udpBytes, icmpCnt, icmpBytes int64
	var mu sync.Mutex

	fn := func(data []byte) int {
		err := dec.DecodeLayers(data, firstLayer, &decoded)
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

		mu.Lock()
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

		mu.Unlock()

		return 0
	}

	nfl := nflog.NewNfLog(e.GroupId, fn)
	defer nfl.Close()

	ticker := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-ticker.C:
			mu.Lock()
			ipPps := ipCnt
			ipRate := float64(ipBytes*8/1000) / 1000
			tcpPps := tcpCnt
			tcpRate := float64(tcpBytes*8/1000) / 1000
			udpPps := udpCnt
			udpRate := float64(udpBytes*8/1000) / 1000
			icmpPps := icmpCnt
			icmpRate := float64(icmpBytes*8/1000) / 1000
			mu.Unlock()

			fmt.Printf("IpPPS: %d, IpRate: %.2f, TcpPPS: %d, TcpRate: %.2f, UdpPPS: %d, UdpRate: %.2f, IcmpPPS: %d, IcmpRate: %.2f\n",
				ipPps, ipRate, tcpPps, tcpRate, udpPps, udpRate, icmpPps, icmpRate)

			mu.Lock()
			ipCnt = 0
			ipBytes = 0
			tcpCnt = 0
			tcpBytes = 0
			udpCnt = 0
			udpBytes = 0
			icmpCnt = 0
			icmpBytes = 0
			mu.Unlock()
		}
	}
}
