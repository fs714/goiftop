package accounting

import (
	"sync"
)

const DefaultL3FlowCollectionSize = 300
const DefaultL4FlowCollectionSize = 600
const DefaultFlowCollectionHistorySize = 300

var FlowPool = sync.Pool{
	New: func() interface{} { return new(Flow) },
}

type FlowFingerprint struct {
	SrcAddr  string
	DstAddr  string
	SrcPort  uint16
	DstPort  uint16
	Protocol string
}

type Flow struct {
	FlowFingerprint
	InboundBytes     int64
	InboundPackets   int64
	InboundDuration  int64
	OutboundBytes    int64
	OutboundPackets  int64
	OutboundDuration int64
}

type FlowTimestamp struct {
	Start int64
	End   int64
}

func (t *FlowTimestamp) Offset(offset int64) (ts FlowTimestamp) {
	ts.Start = t.Start + offset
	ts.End = t.End + offset

	return
}

type FlowCollection struct {
	InterfaceName string
	FlowTimestamp
	L3FlowMap map[FlowFingerprint]*Flow
	L4FlowMap map[FlowFingerprint]*Flow
	Mu        *sync.Mutex
}

func NewFlowCollection(ifaceName string) (flowCol *FlowCollection) {
	flowCol = &FlowCollection{
		InterfaceName: ifaceName,
		L3FlowMap:     make(map[FlowFingerprint]*Flow, DefaultL3FlowCollectionSize),
		L4FlowMap:     make(map[FlowFingerprint]*Flow, DefaultL4FlowCollectionSize),
		Mu:            &sync.Mutex{},
	}

	return
}

func (c *FlowCollection) SetTimestamp(start int64, end int64) {
	c.Start = start
	c.End = end
}

func (c *FlowCollection) UpdateL3Inbound(flowFp FlowFingerprint, numBytes int64, numPkts int64) {
	flow, ok := c.L3FlowMap[flowFp]
	if !ok {
		f := FlowPool.Get().(*Flow)
		f.FlowFingerprint = flowFp
		f.InboundBytes = numBytes
		f.InboundPackets = numPkts
		f.InboundDuration = 0
		f.OutboundBytes = 0
		f.OutboundPackets = 0
		f.OutboundDuration = 0
		c.L3FlowMap[flowFp] = f
	} else {
		flow.InboundBytes += numBytes
		flow.InboundPackets += numPkts
	}
}

func (c *FlowCollection) UpdateL3Outbound(flowFp FlowFingerprint, numBytes int64, numPkts int64) {
	flow, ok := c.L3FlowMap[flowFp]
	if !ok {
		f := FlowPool.Get().(*Flow)
		f.FlowFingerprint = flowFp
		f.InboundBytes = 0
		f.InboundPackets = 0
		f.InboundDuration = 0
		f.OutboundBytes = numBytes
		f.OutboundPackets = numPkts
		f.OutboundDuration = 0
		c.L3FlowMap[flowFp] = f
	} else {
		flow.OutboundBytes += numBytes
		flow.OutboundPackets += numPkts
	}
}

func (c *FlowCollection) UpdateL4Inbound(flowFp FlowFingerprint, numBytes int64, numPkts int64) {
	flow, ok := c.L4FlowMap[flowFp]
	if !ok {
		f := FlowPool.Get().(*Flow)
		f.FlowFingerprint = flowFp
		f.InboundBytes = numBytes
		f.InboundPackets = numPkts
		f.InboundDuration = 0
		f.OutboundBytes = 0
		f.OutboundPackets = 0
		f.OutboundDuration = 0
		c.L4FlowMap[flowFp] = f
	} else {
		flow.InboundBytes += numBytes
		flow.InboundPackets += numPkts
	}
}

func (c *FlowCollection) UpdateL4Outbound(flowFp FlowFingerprint, numBytes int64, numPkts int64) {
	flow, ok := c.L4FlowMap[flowFp]
	if !ok {
		f := FlowPool.Get().(*Flow)
		f.FlowFingerprint = flowFp
		f.InboundBytes = 0
		f.InboundPackets = 0
		f.InboundDuration = 0
		f.OutboundBytes = numBytes
		f.OutboundPackets = numPkts
		f.OutboundDuration = 0
		c.L4FlowMap[flowFp] = f
	} else {
		flow.OutboundBytes += numBytes
		flow.OutboundPackets += numPkts
	}
}

func (c *FlowCollection) UpdateByFlowCol(fc *FlowCollection) {
	for _, f := range fc.L3FlowMap {
		flow, ok := c.L3FlowMap[f.FlowFingerprint]
		if !ok {
			ff := FlowPool.Get().(*Flow)
			*ff = *f
			c.L3FlowMap[f.FlowFingerprint] = ff
		} else {
			flow.InboundBytes += f.InboundBytes
			flow.InboundPackets += f.InboundPackets
			flow.InboundDuration += f.InboundDuration
			flow.OutboundBytes += f.OutboundBytes
			flow.OutboundPackets += f.OutboundPackets
			flow.OutboundDuration += f.OutboundDuration
		}
	}

	for _, f := range fc.L4FlowMap {
		flow, ok := c.L4FlowMap[f.FlowFingerprint]
		if !ok {
			ff := FlowPool.Get().(*Flow)
			*ff = *f
			c.L4FlowMap[f.FlowFingerprint] = ff
		} else {
			flow.InboundBytes += f.InboundBytes
			flow.InboundPackets += f.InboundPackets
			flow.InboundDuration += f.InboundDuration
			flow.OutboundBytes += f.OutboundBytes
			flow.OutboundPackets += f.OutboundPackets
			flow.OutboundDuration += f.OutboundDuration
		}
	}
}

func (c *FlowCollection) Copy() (flowCol *FlowCollection) {
	flowCol = &FlowCollection{
		InterfaceName: c.InterfaceName,
		FlowTimestamp: c.FlowTimestamp,
		L3FlowMap:     make(map[FlowFingerprint]*Flow, len(c.L3FlowMap)),
		L4FlowMap:     make(map[FlowFingerprint]*Flow, len(c.L4FlowMap)),
		Mu:            &sync.Mutex{},
	}

	for k := range c.L3FlowMap {
		f := FlowPool.Get().(*Flow)
		*f = *c.L3FlowMap[k]
		flowCol.L3FlowMap[k] = f
	}

	for k := range c.L4FlowMap {
		f := FlowPool.Get().(*Flow)
		*f = *c.L4FlowMap[k]
		flowCol.L4FlowMap[k] = f
	}

	return
}

func (c *FlowCollection) Reset() {
	for _, v := range c.L3FlowMap {
		FlowPool.Put(v)
	}

	for _, v := range c.L4FlowMap {
		FlowPool.Put(v)
	}

	c.L3FlowMap = make(map[FlowFingerprint]*Flow, DefaultL3FlowCollectionSize)
	c.L4FlowMap = make(map[FlowFingerprint]*Flow, DefaultL4FlowCollectionSize)
}

type FlowCollectionHistory struct {
	InterfaceName  string
	HistCollection map[FlowTimestamp]*FlowCollection
	LastTimestamp  FlowTimestamp
	Mu             *sync.Mutex
}

func NewFlowCollectionHistory(ifaceName string) (flowColHist *FlowCollectionHistory) {
	flowColHist = &FlowCollectionHistory{
		InterfaceName:  ifaceName,
		HistCollection: make(map[FlowTimestamp]*FlowCollection, DefaultFlowCollectionHistorySize),
		Mu:             &sync.Mutex{},
	}

	return
}

func (h *FlowCollectionHistory) SetLastTimestamp(ts FlowTimestamp) {
	h.LastTimestamp = ts
}

func (h *FlowCollectionHistory) Retention(before int64) {
	for k := range h.HistCollection {
		if k.End < before {
			delete(h.HistCollection, k)
		}
	}
}

/*
Assume duration = 5, flow timestamp list is aggregated as below:
10, 11, | 12, 13, 14, 15, 16, | 17, 18, 19, 20, 21, | 22, 23, 24, 25, 26(LastTimestamp.End)
*/
func (h *FlowCollectionHistory) AggregationByDuration(duration int64) (fc *FlowCollection, timestamp *FlowTimestamp) {
	fc = NewFlowCollection(h.InterfaceName)
	h.Mu.Lock()
	lastTs := h.LastTimestamp
	h.Mu.Unlock()
	timestamp = &FlowTimestamp{
		Start: lastTs.Offset(-duration).Start + 1,
		End:   lastTs.End,
	}

	for ts := lastTs; lastTs.End-ts.End < duration; ts = ts.Offset(-1) {
		h.Mu.Lock()
		fcSample, ok := h.HistCollection[ts]
		h.Mu.Unlock()
		if !ok {
			continue
		}

		fc.Mu.Lock()
		fcSample.Mu.Lock()
		fc.UpdateByFlowCol(fcSample)
		fc.Mu.Unlock()
		fcSample.Mu.Unlock()
	}

	return
}
