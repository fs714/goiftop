package engine

import (
	"errors"
	"github.com/fs714/goiftop/accounting"
	"github.com/fs714/goiftop/utils/log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func NewLibPcapEngine(ifaceName, bpfFilter string, direction pcap.Direction, snaplen int32, isDecodeL4 bool, ch chan *accounting.FlowCollection) (engine *LibPcapEngine) {
	engine = &LibPcapEngine{
		IfaceName:            ifaceName,
		BpfFilter:            bpfFilter,
		Direction:            direction,
		SnapLen:              snaplen,
		IsDecodeL4:           isDecodeL4,
		NotifyChannel:        ch,
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
	NotifyChannel        chan *accounting.FlowCollection
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

func (e *LibPcapEngine) GetNotifyChannel() chan *accounting.FlowCollection {
	return e.NotifyChannel
}

func (e *LibPcapEngine) StartEngine() (err error) {
	go Nofify(e)
	err = e.StartCapture()

	return
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
