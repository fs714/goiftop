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

func NewAfpacketEngine(ifaceName string, direction pcap.Direction, isDecodeL4 bool, ch chan accounting.FlowCollection) (engine *AfpacketEngine) {
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
	NotifyChannel        chan accounting.FlowCollection
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

func (e *AfpacketEngine) GetNotifyChannel() chan accounting.FlowCollection {
	return e.NotifyChannel
}

func (e *AfpacketEngine) StartEngine(accd *accounting.Accounting) (err error) {
	err = e.StartCapture()

	return
}

func (e *AfpacketEngine) StartCapture() (err error) {
	afPkt, err := driver.NewAfPacket(e.IfaceName, e.SnapLen, e.Direction, e.MmapBufferSizeMb, e.UseVlan)
	if err != nil {
		log.Errorf("failed to new afpacket driver with err: %s", err.Error())
		return
	}
	defer afPkt.Close()

	dataCh := make(chan []byte, DefaultPacketDataChannelSize)
	feedbackCh := make(chan struct{})
	go afPkt.Loop(dataCh, feedbackCh)

	capture := NewCapture(e)
	firstLayer := capture.Dec.GetFirstLayerType(afPkt.Handle.LinkType())
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
