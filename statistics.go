package main

import (
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const FlowAgingTime = 10

type L3Flow struct {
	Type             string
	Addr             [2]string
	TotalBytes       [2]int64
	DeltaBytes       [2]int64
	ZeroDeltaCounter int
}

type L4Flow struct {
	Protocol         string
	Addr             [2]string
	Port             [2]string
	TotalBytes       [2]int64
	DeltaBytes       [2]int64
	ZeroDeltaCounter int
}

func NewIface(ifaceName string) (iface *Iface) {
	return &Iface{
		Name:    ifaceName,
		L3Flows: make(map[string]*L3Flow),
		L4Flows: make(map[string]*L4Flow),
	}
}

type Iface struct {
	Name    string
	L3Flows map[string]*L3Flow
	L4Flows map[string]*L4Flow
	Lock    sync.Mutex
}

func (i *Iface) UpdateL3Flow(l3Type string, srcAddr string, dstAddr string, length int) {
	i.Lock.Lock()
	var l3f *L3Flow
	var ok bool
	if l3f, ok = i.L3Flows[l3Type+"_"+srcAddr+"_"+dstAddr]; ok {
		l3f.TotalBytes[0] += int64(length)
		l3f.DeltaBytes[0] += int64(length)
	} else if l3f, ok = i.L3Flows[l3Type+"_"+dstAddr+"_"+srcAddr]; ok {
		l3f.TotalBytes[1] += int64(length)
		l3f.DeltaBytes[1] += int64(length)
	} else {
		l3f = &L3Flow{
			Type:       l3Type,
			Addr:       [2]string{srcAddr, dstAddr},
			TotalBytes: [2]int64{int64(length), 0},
			DeltaBytes: [2]int64{int64(length), 0},
		}
		i.L3Flows[l3Type+"_"+srcAddr+"_"+dstAddr] = l3f
	}
	i.Lock.Unlock()
}

func (i *Iface) UpdateL4Flow(l4Protocol string, srcAddr string, dstAddr string, srcPort string, dstPort string, length int) {
	i.Lock.Lock()
	var l4f *L4Flow
	var ok bool
	if l4f, ok = i.L4Flows[l4Protocol+"_"+srcAddr+":"+srcPort+"_"+dstAddr+":"+dstPort]; ok {
		l4f.TotalBytes[0] += int64(length)
		l4f.DeltaBytes[0] += int64(length)
	} else if l4f, ok = i.L4Flows[l4Protocol+"_"+dstAddr+":"+dstPort+"_"+srcAddr+":"+srcPort]; ok {
		l4f.TotalBytes[1] += int64(length)
		l4f.DeltaBytes[1] += int64(length)
	} else {
		l4f = &L4Flow{
			Protocol:   l4Protocol,
			Addr:       [2]string{srcAddr, dstAddr},
			Port:       [2]string{srcPort, dstPort},
			TotalBytes: [2]int64{int64(length), 0},
			DeltaBytes: [2]int64{int64(length), 0},
		}
		i.L4Flows[l4Protocol+"_"+srcAddr+":"+srcPort+"_"+dstAddr+":"+dstPort] = l4f
	}
	i.Lock.Unlock()
}

func (i *Iface) ResetDeltaBytes() {
	i.Lock.Lock()
	for k, v := range i.L3Flows {
		if v.DeltaBytes[0] == 0 && v.DeltaBytes[1] == 0 {
			v.ZeroDeltaCounter += 1
			if v.ZeroDeltaCounter*duration > FlowAgingTime {
				delete(i.L3Flows, k)
			}
		} else {
			v.DeltaBytes[0] = 0
			v.DeltaBytes[1] = 0
		}
	}

	if enableLayer4 {
		for k, v := range i.L4Flows {
			if v.DeltaBytes[0] == 0 && v.DeltaBytes[1] == 0 {
				v.ZeroDeltaCounter += 1
				if v.ZeroDeltaCounter*duration > FlowAgingTime {
					delete(i.L4Flows, k)
				}
			} else {
				v.DeltaBytes[0] = 0
				v.DeltaBytes[1] = 0
			}
		}
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
			L3Flows: make(map[string]*L3Flow),
			L4Flows: make(map[string]*L4Flow),
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
