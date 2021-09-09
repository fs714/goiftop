package engine

import (
	"errors"
	"fmt"
	"github.com/fs714/goiftop/accounting"
	"github.com/fs714/goiftop/decoder"
	"github.com/fs714/goiftop/utils/log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/bpf"
	"os"
	"strings"
	"time"
)

type afpacketHandle struct {
	TPacket *afpacket.TPacket
}

func newAfpacketHandle(device string, snaplen int, blockSize int, numBlocks int, useVLAN bool, timeout time.Duration) (*afpacketHandle, error) {
	h := &afpacketHandle{}
	var err error

	if device == "any" {
		h.TPacket, err = afpacket.NewTPacket(
			afpacket.OptFrameSize(snaplen),
			afpacket.OptBlockSize(blockSize),
			afpacket.OptNumBlocks(numBlocks),
			afpacket.OptAddVLANHeader(useVLAN),
			afpacket.OptPollTimeout(timeout),
			afpacket.SocketRaw,
			afpacket.TPacketVersion3)
	} else {
		h.TPacket, err = afpacket.NewTPacket(
			afpacket.OptInterface(device),
			afpacket.OptFrameSize(snaplen),
			afpacket.OptBlockSize(blockSize),
			afpacket.OptNumBlocks(numBlocks),
			afpacket.OptAddVLANHeader(useVLAN),
			afpacket.OptPollTimeout(timeout),
			afpacket.SocketRaw,
			afpacket.TPacketVersion3)
	}
	return h, err
}

// ZeroCopyReadPacketData satisfies ZeroCopyPacketDataSource interface
func (h *afpacketHandle) ZeroCopyReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	return h.TPacket.ZeroCopyReadPacketData()
}

// SetBPFFilter translates a BPF filter string into BPF RawInstruction and applies them.
func (h *afpacketHandle) SetBPFFilter(filter string, snaplen int) (err error) {
	pcapBPF, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, snaplen, filter)
	if err != nil {
		return err
	}
	var bpfIns []bpf.RawInstruction
	for _, ins := range pcapBPF {
		bpfIns2 := bpf.RawInstruction{
			Op: ins.Code,
			Jt: ins.Jt,
			Jf: ins.Jf,
			K:  ins.K,
		}
		bpfIns = append(bpfIns, bpfIns2)
	}

	err = h.TPacket.SetBPF(bpfIns)

	return err
}

// LinkType returns ethernet link type.
func (h *afpacketHandle) LinkType() layers.LinkType {
	return layers.LinkTypeEthernet
}

// Close will close afpacket source.
func (h *afpacketHandle) Close() {
	h.TPacket.Close()
}

// SocketStats prints received, dropped, queue-freeze packet stats.
func (h *afpacketHandle) SocketStats() (as afpacket.SocketStats, asv afpacket.SocketStatsV3, err error) {
	return h.TPacket.SocketStats()
}

// afpacketComputeSize computes the block_size and the num_blocks in such a way that the
// allocated mmap buffer is close to but smaller than target_size_mb.
// The restriction is that the block_size must be divisible by both the
// frame size and page size.
func afpacketComputeSize(targetSizeMb int, snaplen int, pageSize int) (
	frameSize int, blockSize int, numBlocks int, err error) {

	if snaplen < pageSize {
		frameSize = pageSize / (pageSize / snaplen)
	} else {
		frameSize = (snaplen/pageSize + 1) * pageSize
	}

	// 128 is the default from the gopacket library so just use that
	blockSize = frameSize * 128
	numBlocks = (targetSizeMb * 1024 * 1024) / blockSize

	if numBlocks == 0 {
		return 0, 0, 0, fmt.Errorf("interface buffersize is too small")
	}

	return frameSize, blockSize, numBlocks, nil
}

func NewAfpacketEngine(ifaceName string, direction pcap.Direction, isDecodeL4 bool) (engine *AfpacketEngine) {
	engine = &AfpacketEngine{
		IfaceName:            ifaceName,
		Direction:            direction,
		SnapLen:              65535,
		MmapBufferSizeMb:     16,
		UseVlan:              false,
		IsDecodeL4:           isDecodeL4,
		FlowCol:              accounting.NewFlowCollection(ifaceName),
		FlowColResetInterval: DefaultFlowColResetInterval,
	}

	return
}

type AfpacketEngine struct {
	IfaceName            string
	Direction            pcap.Direction
	SnapLen              int
	MmapBufferSizeMb     int
	UseVlan              bool
	IsDecodeL4           bool
	FlowCol              *accounting.FlowCollection
	FlowColResetInterval int64
}

func (e *AfpacketEngine) StartInform(accd *accounting.Accounting) {
	Inform(accd, e.FlowCol, e.FlowColResetInterval)
}

func (e *AfpacketEngine) StartCapture() (err error) {
	szFrame, szBlock, numBlocks, err := afpacketComputeSize(e.MmapBufferSizeMb, e.SnapLen, os.Getpagesize())
	if err != nil {
		log.Errorf("failed to calc frame size, block size and block num with err: %s", err.Error())
		return
	}

	handle, err := newAfpacketHandle(e.IfaceName, szFrame, szBlock, numBlocks, e.UseVlan, pcap.BlockForever)
	if err != nil {
		log.Errorf("failed to open live interface %s by AfpacketEngine with err: %s", e.IfaceName, err.Error())
		return
	}

	var bpfFilter string
	if e.Direction == pcap.DirectionIn {
		bpfFilter = "inbound"
	} else if e.Direction == pcap.DirectionOut {
		bpfFilter = "outbound"
	}

	err = handle.SetBPFFilter(bpfFilter, e.SnapLen)
	if err != nil {
		log.Errorf("failed to set direction by AfpacketEngine with err: %s", err.Error())
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

func (e *AfpacketEngine) StartEngine(accd *accounting.Accounting) (err error) {
	go e.StartInform(accd)
	err = e.StartCapture()

	return
}
