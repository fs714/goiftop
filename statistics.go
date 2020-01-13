package main

import (
	"github.com/fs714/goiftop/utils/queue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"sync"
)

const TotalBytesQueueLen = 61

var Stats = &Statistics{
	ifaces: make(map[string]*Iface),
}

type FlowSnapshot struct {
	Protocol           string
	SourceAddress      string // Include port if it is L4 flow
	DestinationAddress string // Include port if it is L4 flow
	UpStreamRate1      int64
	DownStreamRate1    int64
	UpStreamRate15     int64
	DownStreamRate15   int64
	UpStreamRate60     int64
	DownStreamRate60   int64
}

var L3FlowSnapshots = make([]*FlowSnapshot, 0, 0)
var L4FlowSnapshots = make([]*FlowSnapshot, 0, 0)

type Flow struct {
	Protocol         string
	Addr             [2]string
	Port             [2]string
	TotalBytes       [2]int64
	TotalBytesQueue  *queue.FixQueue
	ZeroDeltaCounter int
}

func (f *Flow) GetSnapshot() (ss *FlowSnapshot) {
	var upStreamRate1, downStreamRate1, upStreamRate15, downStreamRate15, upStreamRate60, downStreamRate60 int64
	if f.TotalBytesQueue.Get(-2) != nil {
		totalBytesPrev := f.TotalBytesQueue.Get(-2).([2]int64)
		totalBytesCur := f.TotalBytesQueue.Get(-1).([2]int64)
		upStreamRate1 = (totalBytesCur[0] - totalBytesPrev[0]) * 8
		downStreamRate1 = (totalBytesCur[1] - totalBytesPrev[1]) * 8
	} else {
		upStreamRate1 = 0
		downStreamRate1 = 0
	}

	if f.TotalBytesQueue.Get(-16) != nil {
		totalBytesPrev := f.TotalBytesQueue.Get(-16).([2]int64)
		totalBytesCur := f.TotalBytesQueue.Get(-1).([2]int64)
		upStreamRate15 = (totalBytesCur[0] - totalBytesPrev[0]) * 8 / 15
		downStreamRate15 = (totalBytesCur[1] - totalBytesPrev[1]) * 8 / 15
	} else {
		upStreamRate15 = 0
		downStreamRate15 = 0
	}

	if f.TotalBytesQueue.Get(-61) != nil {
		totalBytesPrev := f.TotalBytesQueue.Get(-61).([2]int64)
		totalBytesCur := f.TotalBytesQueue.Get(-1).([2]int64)
		upStreamRate60 = (totalBytesCur[0] - totalBytesPrev[0]) * 8 / 60
		downStreamRate60 = (totalBytesCur[1] - totalBytesPrev[1]) * 8 / 60
	} else {
		upStreamRate60 = 0
		downStreamRate60 = 0
	}

	var srcAddr, dstAddr string
	if f.Port[0] == "" && f.Port[1] == "" {
		srcAddr = f.Addr[0]
		dstAddr = f.Addr[1]
	} else {
		srcAddr = f.Addr[0] + ":" + f.Port[0]
		dstAddr = f.Addr[1] + ":" + f.Port[1]
	}

	fss := FlowSnapshot{
		Protocol:           f.Protocol,
		SourceAddress:      srcAddr,
		DestinationAddress: dstAddr,
		UpStreamRate1:      upStreamRate1,
		DownStreamRate1:    downStreamRate1,
		UpStreamRate15:     upStreamRate15,
		DownStreamRate15:   downStreamRate15,
		UpStreamRate60:     upStreamRate60,
		DownStreamRate60:   downStreamRate60,
	}

	ss = &fss
	return
}

func NewIface(ifaceName string) (iface *Iface) {
	return &Iface{
		Name:    ifaceName,
		L3Flows: make(map[string]*Flow),
		L4Flows: make(map[string]*Flow),
	}
}

type Iface struct {
	Name    string
	L3Flows map[string]*Flow
	L4Flows map[string]*Flow
	Lock    sync.Mutex
}

func (i *Iface) UpdateL3Flow(l3Type string, srcAddr string, dstAddr string, length int) {
	i.Lock.Lock()
	var l3f *Flow
	var ok bool
	if l3f, ok = i.L3Flows[l3Type+"_"+srcAddr+"_"+dstAddr]; ok {
		l3f.TotalBytes[0] += int64(length)
	} else if l3f, ok = i.L3Flows[l3Type+"_"+dstAddr+"_"+srcAddr]; ok {
		l3f.TotalBytes[1] += int64(length)
	} else {
		l3f = &Flow{
			Protocol:        l3Type,
			Addr:            [2]string{srcAddr, dstAddr},
			TotalBytes:      [2]int64{int64(length), 0},
			TotalBytesQueue: queue.NewFixQueue(TotalBytesQueueLen),
		}
		i.L3Flows[l3Type+"_"+srcAddr+"_"+dstAddr] = l3f
	}
	i.Lock.Unlock()
}

func (i *Iface) UpdateL4Flow(l4Protocol string, srcAddr string, dstAddr string, srcPort string, dstPort string, length int) {
	i.Lock.Lock()
	var l4f *Flow
	var ok bool
	if l4f, ok = i.L4Flows[l4Protocol+"_"+srcAddr+":"+srcPort+"_"+dstAddr+":"+dstPort]; ok {
		l4f.TotalBytes[0] += int64(length)
	} else if l4f, ok = i.L4Flows[l4Protocol+"_"+dstAddr+":"+dstPort+"_"+srcAddr+":"+srcPort]; ok {
		l4f.TotalBytes[1] += int64(length)
	} else {
		l4f = &Flow{
			Protocol:        l4Protocol,
			Addr:            [2]string{srcAddr, dstAddr},
			Port:            [2]string{srcPort, dstPort},
			TotalBytes:      [2]int64{int64(length), 0},
			TotalBytesQueue: queue.NewFixQueue(TotalBytesQueueLen),
		}
		i.L4Flows[l4Protocol+"_"+srcAddr+":"+srcPort+"_"+dstAddr+":"+dstPort] = l4f
	}
	i.Lock.Unlock()
}

func (i *Iface) UpdateL3FlowQueue() {
	i.Lock.Lock()
	for k, v := range i.L3Flows {
		if v.TotalBytesQueue.Get(0) != nil {
			totalBytesOldest := v.TotalBytesQueue.Get(0).([2]int64)
			totalBytesLatest := v.TotalBytesQueue.Get(-1).([2]int64)
			if totalBytesOldest[0] == totalBytesLatest[0] && totalBytesOldest[1] == totalBytesLatest[1] {
				delete(i.L3Flows, k)
				continue
			}
		}

		v.TotalBytesQueue.Append(v.TotalBytes)
	}
	i.Lock.Unlock()
}

func (i *Iface) UpdateL4FlowQueue() {
	i.Lock.Lock()
	for k, v := range i.L4Flows {
		if v.TotalBytesQueue.Get(0) != nil {
			totalBytesOldest := v.TotalBytesQueue.Get(0).([2]int64)
			totalBytesLatest := v.TotalBytesQueue.Get(-1).([2]int64)
			if totalBytesOldest[0] == totalBytesLatest[0] && totalBytesOldest[1] == totalBytesLatest[1] {
				delete(i.L3Flows, k)
				continue
			}
		}

		v.TotalBytesQueue.Append(v.TotalBytes)
	}
	i.Lock.Unlock()
}

type Statistics struct {
	ifaces map[string]*Iface
}

func (s *Statistics) GetIface(ifaceName string) (iface *Iface) {
	var ok bool
	iface, ok = s.ifaces[ifaceName]
	if !ok {
		iface = &Iface{
			Name:    ifaceName,
			L3Flows: make(map[string]*Flow),
			L4Flows: make(map[string]*Flow),
		}
		s.ifaces[ifaceName] = iface
	}

	return
}

func (s *Statistics) PacketHandler(ifaceName string, pkg gopacket.Packet) {
	iface := s.GetIface(ifaceName)
	var l3Type, l4Protocol string
	var srcAddr, dstAddr string
	var srcPort, dstPort string
	var l3Len, l4Len int

	for _, ly := range pkg.Layers() {
		switch ly.LayerType() {
		case layers.LayerTypeIPv4:
			l := ly.(*layers.IPv4)
			l3Type = "ipv4"
			srcAddr = l.SrcIP.String()
			dstAddr = l.DstIP.String()
			l3Len = len(l.LayerPayload())
		case layers.LayerTypeTCP:
			l := ly.(*layers.TCP)
			l4Protocol = "tcp"
			srcPort = l.SrcPort.String()
			dstPort = l.DstPort.String()
			l4Len = len(l.LayerPayload())
		case layers.LayerTypeUDP:
			l := ly.(*layers.UDP)
			l4Protocol = "udp"
			srcPort = l.SrcPort.String()
			dstPort = l.DstPort.String()
			l4Len = len(l.LayerPayload())
		case layers.LayerTypeICMPv4:
			l := ly.(*layers.ICMPv4)
			l4Protocol = "icmp"
			l4Len = len(l.LayerPayload())
		}
	}

	if l3Type == "" || l4Protocol == "" {
		return
	}

	iface.UpdateL3Flow(l3Type, srcAddr, dstAddr, l3Len)
	if enableLayer4 {
		iface.UpdateL4Flow(l4Protocol, srcAddr, dstAddr, srcPort, dstPort, l4Len)
	}
}
