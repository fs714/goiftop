package accounting

import (
	"context"
	"github.com/fs714/goiftop/utils/log"
	"time"
)

const DefaultFlowDbSize = 2
const DefaultStatChannelSize = 16
const DefaultRotateInterval = 5

var GlobalAcct *Accounting

type Accounting struct {
	FlowAccd  map[string]*FlowCollectionHistory
	Retention int64
	Ch        chan *FlowCollection
}

func NewAccounting() (acct *Accounting) {
	acct = &Accounting{
		FlowAccd: make(map[string]*FlowCollectionHistory, DefaultFlowDbSize),
		Ch:       make(chan *FlowCollection, DefaultStatChannelSize),
	}

	return
}

func (a *Accounting) AddInterface(ifaceName string) {
	a.FlowAccd[ifaceName] = NewFlowCollectionHistory(ifaceName)
}

func (a *Accounting) SetRetention(t int64) {
	a.Retention = t
}

func (a *Accounting) Start(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(DefaultRotateInterval) * time.Second)
	for {
		select {
		case <-ctx.Done():
			log.Infoln("statistic exit")
			return
		case <-ticker.C:
			if a.Retention > 0 {
				before := time.Now().Unix() - a.Retention
				for _, v := range a.FlowAccd {
					v.Mu.Lock()
					v.Retention(before)
					v.Mu.Unlock()
				}
			}
		case flowCol := <-a.Ch:
			flowColHist, ok := a.FlowAccd[flowCol.InterfaceName]
			if !ok {
				log.Errorf("invalid interface name: %s", flowCol.InterfaceName)
				continue
			}

			flowColHist.Mu.Lock()
			fc, ok := flowColHist.HistCollection[flowCol.FlowTimestamp]
			if !ok {
				flowColCopy := *flowCol
				flowColHist.HistCollection[flowCol.FlowTimestamp] = &flowColCopy
				flowColHist.SetLastTimestamp(flowCol.FlowTimestamp)
			} else {
				fc.Mu.Lock()
				fc.UpdateByFlowCol(flowCol)
				fc.Mu.Unlock()
				flowColHist.SetLastTimestamp(flowCol.FlowTimestamp)
			}
			flowColHist.Mu.Unlock()

			flowCol.Reset()
			flowCol.Mu.Unlock()
		}
	}
}
