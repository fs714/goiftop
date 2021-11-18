package engine

import (
	"errors"
	"fmt"
	"github.com/fs714/goiftop/accounting"
	"github.com/fs714/goiftop/utils/log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/bpf"
	"os"
	"time"
)

type AfpacketHandle struct {
	TPacket *afpacket.TPacket
}

func NewAfpacketHandle(device string, snaplen int, blockSize int, numBlocks int, useVLAN bool, timeout time.Duration) (*AfpacketHandle, error) {
	h := &AfpacketHandle{}
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
func (h *AfpacketHandle) ZeroCopyReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	return h.TPacket.ZeroCopyReadPacketData()
}

// SetBPFFilter translates a BPF filter string into BPF RawInstruction and applies them.
func (h *AfpacketHandle) SetBPFFilter(filter string, snaplen int) (err error) {
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
func (h *AfpacketHandle) LinkType() layers.LinkType {
	return layers.LinkTypeEthernet
}

// Close will close afpacket source.
func (h *AfpacketHandle) Close() {
	h.TPacket.Close()
}

// SocketStats prints received, dropped, queue-freeze packet stats.
func (h *AfpacketHandle) SocketStats() (as afpacket.SocketStats, asv afpacket.SocketStatsV3, err error) {
	return h.TPacket.SocketStats()
}

// AfpacketComputeSize computes the block_size and the num_blocks in such a way that the
// allocated mmap buffer is close to but smaller than target_size_mb.
// The restriction is that the block_size must be divisible by both the
// frame size and page size.
func AfpacketComputeSize(targetSizeMb int, snaplen int, pageSize int) (
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

func NewAfpacketEngine(ifaceName string, direction pcap.Direction, isDecodeL4 bool, ch chan *accounting.FlowCollection) (engine *AfpacketEngine) {
	engine = &AfpacketEngine{
		IfaceName:            ifaceName,
		Direction:            direction,
		SnapLen:              65535,
		MmapBufferSizeMb:     16,
		UseVlan:              false,
		IsDecodeL4:           isDecodeL4,
		NotifyChannel:        ch,
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
	NotifyChannel        chan *accounting.FlowCollection
	FlowCol              *accounting.FlowCollection
	FlowColResetInterval int64
}

func (e *AfpacketEngine) GetDirection() pcap.Direction {
	return e.Direction
}

func (e *AfpacketEngine) GetFlowCollection() *accounting.FlowCollection {
	return e.FlowCol
}

func (e *AfpacketEngine) GetResetInterval() int64 {
	return e.FlowColResetInterval
}

func (e *AfpacketEngine) GetIsDecodeL4() bool {
	return e.IsDecodeL4
}

func (e *AfpacketEngine) GetNotifyChannel() chan *accounting.FlowCollection {
	return e.NotifyChannel
}

func (e *AfpacketEngine) StartEngine() (err error) {
	go Nofify(e)
	err = e.StartCapture()

	return
}

func (e *AfpacketEngine) StartCapture() (err error) {
	szFrame, szBlock, numBlocks, err := AfpacketComputeSize(e.MmapBufferSizeMb, e.SnapLen, os.Getpagesize())
	if err != nil {
		log.Errorf("failed to calc frame size, block size and block num with err: %s", err.Error())
		return
	}

	handle, err := NewAfpacketHandle(e.IfaceName, szFrame, szBlock, numBlocks, e.UseVlan, pcap.BlockForever)
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

	capture := NewCapture(e)
	firstLayer := capture.Dec.GetFirstLayerType(handle.LinkType())
	if firstLayer == gopacket.LayerTypeZero {
		err = errors.New("failed to find first decode layer type")
		log.Errorln(err.Error())
		return
	}
	capture.SetFirstLayer(firstLayer)

	var data []byte
	for {
		data, _, err = handle.ZeroCopyReadPacketData()
		if err != nil {
			log.Errorf("error getting packet: %s", err.Error())
			continue
		}

		capture.DecodeAndAccount(data)
	}
}
