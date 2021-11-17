// # iptables -I OUTPUT -p icmp -j NFLOG --nflog-group 100
// # iptables -t raw -A PREROUTING -i eth1 -j NFLOG --nflog-group 2 --nflog-range 64 --nflog-threshold 10
// # iptables -t mangle -A POSTROUTING -o eth1 -j NFLOG --nflog-group 5 --nflog-range 64 --nflog-threshold 10

package engine

import (
	"github.com/fs714/goiftop/accounting"
	"github.com/fs714/goiftop/engine/nflog"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func NewNflogEngine(ifaceName string, groupId int, direction pcap.Direction, isDecodeL4 bool) (engine *NflogEngine) {
	engine = &NflogEngine{
		IfaceName:            ifaceName,
		GroupId:              groupId,
		Direction:            direction,
		IsDecodeL4:           isDecodeL4,
		FlowCol:              accounting.NewFlowCollection(ifaceName),
		FlowColResetInterval: DefaultFlowColResetInterval,
	}

	return
}

type NflogEngine struct {
	IfaceName            string
	GroupId              int
	Direction            pcap.Direction
	IsDecodeL4           bool
	FlowCol              *accounting.FlowCollection
	FlowColResetInterval int64
}

func (e *NflogEngine) GetDirection() pcap.Direction {
	return e.Direction
}

func (e *NflogEngine) GetFlowCollection() *accounting.FlowCollection {
	return e.FlowCol
}

func (e *NflogEngine) GetResetInterval() int64 {
	return e.FlowColResetInterval
}

func (e *NflogEngine) GetIsDecodeL4() bool {
	return e.IsDecodeL4
}

func (e *NflogEngine) StartEngine(accd *accounting.Accounting) (err error) {
	go e.StartInform(accd)
	err = e.StartCapture()

	return
}

func (e *NflogEngine) StartInform(accd *accounting.Accounting) {
	Inform(accd, e)
}

func (e *NflogEngine) StartCapture() (err error) {
	capture := NewCapture(e)
	firstLayer := layers.LayerTypeIPv4
	capture.SetFirstLayer(firstLayer)

	ch := make(chan []byte, 16)
	nfl := nflog.NewNfLog(e.GroupId, ch)
	defer nfl.Close()

	go nfl.Loop()

	for {
		select {
		case packet := <-ch:
			capture.DecodeAndAccount(packet)
		}
	}
}
