package driver

import (
	"github.com/fs714/goiftop/utils/log"
	"github.com/google/gopacket/pcap"
)

type LibPcap struct {
	Handle  *pcap.Handle
	SnapLen int32
}

func NewLibPcap(iface string, snapLen int32, bpfFilter string, direction pcap.Direction) (libPcap *LibPcap, err error) {
	handle, err := pcap.OpenLive(iface, snapLen, true, pcap.BlockForever)
	if err != nil {
		log.Errorf("failed to open live interface %s by LibPcapEngine with err: %s", iface, err.Error())
		return
	}

	err = handle.SetBPFFilter(bpfFilter)
	if err != nil {
		log.Errorf("failed to set BPF filter %s by LibPcapEngine with err: %s", bpfFilter, err.Error())
		return
	}

	err = handle.SetDirection(direction)
	if err != nil {
		log.Errorf("failed to set direction by LibPcapEngine with err: %s", err.Error())
		return
	}

	libPcap = &LibPcap{
		Handle:  handle,
		SnapLen: snapLen,
	}

	return
}

func (p *LibPcap) Close() {
	p.Handle.Close()
}

func (p *LibPcap) Loop(dataChan chan []byte, feedbackChan chan struct{}) {
	data := make([]byte, p.SnapLen)
	var err error
	for {
		data, _, err = p.Handle.ZeroCopyReadPacketData()
		if err != nil {
			log.Errorf("error getting packet: %s", err.Error())
			continue
		}

		dataChan <- data
		<-feedbackChan
	}
}
