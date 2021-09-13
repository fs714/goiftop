package engine

import (
	"errors"
	"github.com/fs714/goiftop/accounting"
	"github.com/fs714/goiftop/utils/log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
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

func (e *LibPcapEngine) GetDirection() pcap.Direction {
	return e.Direction
}

func (e *LibPcapEngine) GetFlowCollection() *accounting.FlowCollection {
	return e.FlowCol
}

func (e *LibPcapEngine) GetResetInterval() int64 {
	return e.FlowColResetInterval
}

func (e *LibPcapEngine) GetIsDecodeL4() bool {
	return e.IsDecodeL4
}

func (e *LibPcapEngine) StartEngine(accd *accounting.Accounting) (err error) {
	go e.StartInform(accd)
	err = e.StartCapture()

	return
}

func (e *LibPcapEngine) StartInform(accd *accounting.Accounting) {
	Inform(accd, e)
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

	capture := NewCapture(e)

	firstLayer := capture.Dec.GetFirstLayerType(handle.LinkType())
	if firstLayer == gopacket.LayerTypeZero {
		err = errors.New("failed to find first decode layer type")
		log.Errorln(err.Error())
		return
	}

	capture.SetFirstLayer(firstLayer)

	data := make([]byte, e.SnapLen)
	for {
		data, _, err = handle.ZeroCopyReadPacketData()
		if err != nil {
			log.Errorf("error getting packet: %s", err.Error())
			continue
		}

		capture.DecodeAndAccount(data)
	}
}
