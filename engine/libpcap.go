package engine

import (
	"errors"
	"github.com/fs714/goiftop/accounting"
	"github.com/fs714/goiftop/engine/driver"
	"github.com/fs714/goiftop/utils/log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"time"
)

func NewLibPcapEngine(ifaceName, bpfFilter string, direction pcap.Direction, snaplen int32, isDecodeL4 bool, ch chan accounting.FlowCollection) (engine *LibPcapEngine) {
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
	NotifyChannel        chan accounting.FlowCollection
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

func (e *LibPcapEngine) GetNotifyChannel() chan accounting.FlowCollection {
	return e.NotifyChannel
}

func (e *LibPcapEngine) StartEngine(accd *accounting.Accounting) (err error) {
	libPcap, err := driver.NewLibPcap(e.IfaceName, e.SnapLen, e.BpfFilter, e.Direction)
	if err != nil {
		log.Errorf("failed to new libpcap driver with err: %s", err.Error())
		return
	}
	defer libPcap.Close()

	dataCh := make(chan []byte, DefaultPacketDataChannelSize)
	feedbackCh := make(chan struct{})
	go libPcap.Loop(dataCh, feedbackCh)

	capture := NewCapture(e)
	firstLayer := capture.Dec.GetFirstLayerType(libPcap.Handle.LinkType())
	if firstLayer == gopacket.LayerTypeZero {
		err = errors.New("failed to find first decode layer type")
		log.Errorln(err.Error())
		return
	}
	capture.SetFirstLayer(firstLayer)

	ticker := time.NewTicker(time.Duration(e.FlowColResetInterval) * time.Second)
	for {
		select {
		case <-ticker.C:
			Notify(e)
		case packet := <-dataCh:
			capture.DecodeAndAccount(packet)
			feedbackCh <- struct{}{}
		}
	}
}
