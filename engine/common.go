package engine

import (
	"github.com/fs714/goiftop/accounting"
	"time"
)

const LibPcapEngineName = "libpcap"
const AfpacketEngineName = "afpacket"
const NflogEngineName = "nflog"
const DefaultFlowColResetInterval = 1

type PktCapEngine interface {
	StartEngine(*accounting.Accounting) error
}

func Inform(accd *accounting.Accounting, flowCol *accounting.FlowCollection, resetInterval int64) {
	ticker := time.NewTicker(time.Duration(resetInterval) * time.Second)
	for {
		select {
		case <-ticker.C:
			flowCol.Mu.Lock()

			now := time.Now().Unix()
			flowCol.SetTimestamp(now-resetInterval, now)
			accd.Ch <- flowCol

			flowCol.Reset()
		}
	}
}
