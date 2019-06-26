package main

import (
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func NewIface(ifaceName string) (iface *Iface) {
	return &Iface{
		Name:           ifaceName,
		NetworkFlows:   make(map[string]*NetworkFlow),
		TransportFlows: make(map[string]*TransportFlow),
	}
}

type NetworkFlow struct {
	Type             string
	Addr             [2]string
	TotalBytes       [2]int64
	DeltaBytes       [2]int64
	ZeroDeltaCounter int
}

type TransportFlow struct {
	Protocol         string
	Addr             [2]string
	Port             [2]string
	TotalBytes       [2]int64
	DeltaBytes       [2]int64
	ZeroDeltaCounter int
}

type Iface struct {
	Name           string
	NetworkFlows   map[string]*NetworkFlow
	TransportFlows map[string]*TransportFlow
	Lock           sync.Mutex
}

func (i *Iface) UpdateNetworkFlow(networkType string, srcAddr string, dstAddr string, length int) {
	i.Lock.Lock()
	var nf *NetworkFlow
	var ok bool
	if nf, ok = i.NetworkFlows[srcAddr+"_"+dstAddr]; ok {
		nf.TotalBytes[0] += int64(length)
		nf.DeltaBytes[0] += int64(length)
	} else if nf, ok = i.NetworkFlows[dstAddr+"_"+srcAddr]; ok {
		nf.TotalBytes[1] += int64(length)
		nf.DeltaBytes[1] += int64(length)
	} else {
		nf = &NetworkFlow{
			Type:       networkType,
			Addr:       [2]string{srcAddr, dstAddr},
			TotalBytes: [2]int64{int64(length), 0},
			DeltaBytes: [2]int64{int64(length), 0},
		}
		i.NetworkFlows[srcAddr+"_"+dstAddr] = nf
	}
	i.Lock.Unlock()
}

func (i *Iface) UpdateTransportFlow(transportProtocol string, srcAddr string, dstAddr string, srcPort string, dstPort string, length int) {
	i.Lock.Lock()
	var tf *TransportFlow
	var ok bool
	if tf, ok = i.TransportFlows[srcAddr+":"+srcPort+"_"+dstAddr+":"+dstPort]; ok {
		tf.TotalBytes[0] += int64(length)
		tf.DeltaBytes[0] += int64(length)
	} else if tf, ok = i.TransportFlows[dstAddr+":"+dstPort+"_"+srcAddr+":"+srcPort]; ok {
		tf.TotalBytes[1] += int64(length)
		tf.DeltaBytes[1] += int64(length)
	} else {
		tf = &TransportFlow{
			Protocol:   transportProtocol,
			Addr:       [2]string{srcAddr, dstAddr},
			Port:       [2]string{srcPort, dstPort},
			TotalBytes: [2]int64{int64(length), 0},
			DeltaBytes: [2]int64{int64(length), 0},
		}
		i.TransportFlows[srcAddr+":"+srcPort+"_"+dstAddr+":"+dstPort] = tf
	}
	i.Lock.Unlock()
}

func (i *Iface) ResetDeltaBytes() {
	i.Lock.Lock()
	for k, v := range i.NetworkFlows {
		if v.DeltaBytes[0] == 0 && v.DeltaBytes[1] == 0 {
			v.ZeroDeltaCounter += 1
			if v.ZeroDeltaCounter*duration > 10 {
				delete(i.NetworkFlows, k)
			}
		} else {
			v.DeltaBytes[0] = 0
			v.DeltaBytes[1] = 0
		}
	}

	if isTransport {
		for k, v := range i.TransportFlows {
			if v.DeltaBytes[0] == 0 && v.DeltaBytes[1] == 0 {
				v.ZeroDeltaCounter += 1
				if v.ZeroDeltaCounter*duration > 10 {
					delete(i.TransportFlows, k)
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
			Name:           ifaceName,
			NetworkFlows:   make(map[string]*NetworkFlow),
			TransportFlows: make(map[string]*TransportFlow),
		}
		s.ifaces[ifaceName] = iface
	}

	return
}

func (s *Statistics) PacketHandler(ifaceName string, pkg gopacket.Packet) {
	iface := s.GetIface(ifaceName)
	var networkType, transportProtocol string
	var srcAddr, dstAddr string
	var srcPort, dstPort string
	var networkLen, transportLen int

	for _, ly := range pkg.Layers() {
		switch ly.LayerType() {
		case layers.LayerTypeIPv4:
			l := ly.(*layers.IPv4)
			networkType = "ipv4"
			srcAddr = l.SrcIP.String()
			dstAddr = l.DstIP.String()
			networkLen = len(l.LayerPayload())
		case layers.LayerTypeTCP:
			l := ly.(*layers.TCP)
			transportProtocol = "tcp"
			srcPort = l.SrcPort.String()
			dstPort = l.DstPort.String()
			transportLen = len(l.LayerPayload())
		case layers.LayerTypeUDP:
			l := ly.(*layers.UDP)
			transportProtocol = "udp"
			srcPort = l.SrcPort.String()
			dstPort = l.DstPort.String()
			transportLen = len(l.LayerPayload())
		case layers.LayerTypeICMPv4:
			l := ly.(*layers.ICMPv4)
			transportProtocol = "icmp"
			transportLen = len(l.LayerPayload())
		}
	}

	if networkType == "" || transportProtocol == "" {
		return
	}

	iface.UpdateNetworkFlow(networkType, srcAddr, dstAddr, networkLen)
	if isTransport {
		iface.UpdateTransportFlow(transportProtocol, srcAddr, dstAddr, srcPort, dstPort, transportLen)
	}
}
