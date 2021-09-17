package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/fs714/goiftop/accounting"
	"github.com/fs714/goiftop/utils/log"
	"net/http"
	"strconv"
	"time"
)

const Layer3String = "l3"
const Layer4String = "l4"

type Flow struct {
	Layer            string
	SrcAddr          string
	DstAddr          string
	SrcPort          uint16
	DstPort          uint16
	Protocol         string
	InboundBytes     int64
	InboundPackets   int64
	InboundDuration  int64
	OutboundBytes    int64
	OutboundPackets  int64
	OutboundDuration int64
}

type Flows struct {
	RouterId string
	OamAddr  string
	Start    int64
	End      int64
	FLowsMap map[string][]*Flow
}

func WebhookNotifier(ctx context.Context, duration int64, nodeId string, nodeOamAddr string, url string, timeout int) {
	ticker := time.NewTicker(time.Duration(duration) * time.Second)
	for {
		select {
		case <-ctx.Done():
			log.Infoln("webhook notifier exit")
			return
		case <-ticker.C:
			flows := Flows{
				RouterId: nodeId,
				OamAddr:  nodeOamAddr,
				FLowsMap: make(map[string][]*Flow),
			}
			for ifaceName, flowColHist := range accounting.GlobalAcct.FlowAccd {
				fc, ts := flowColHist.AggregationByDuration(duration)

				flows.Start = ts.Start
				flows.End = ts.End

				flowList := make([]*Flow, 0)

				for _, f := range fc.L3FlowMap {
					ff := Flow{
						Layer:            Layer3String,
						SrcAddr:          f.SrcAddr,
						DstAddr:          f.DstAddr,
						SrcPort:          f.SrcPort,
						DstPort:          f.DstPort,
						Protocol:         f.Protocol,
						InboundBytes:     f.InboundBytes,
						InboundPackets:   f.InboundPackets,
						InboundDuration:  f.InboundDuration,
						OutboundBytes:    f.OutboundBytes,
						OutboundPackets:  f.OutboundPackets,
						OutboundDuration: f.OutboundDuration,
					}
					flowList = append(flowList, &ff)
				}

				for _, f := range fc.L4FlowMap {
					ff := Flow{
						Layer:            Layer4String,
						SrcAddr:          f.SrcAddr,
						DstAddr:          f.DstAddr,
						SrcPort:          f.SrcPort,
						DstPort:          f.DstPort,
						Protocol:         f.Protocol,
						InboundBytes:     f.InboundBytes,
						InboundPackets:   f.InboundPackets,
						InboundDuration:  f.InboundDuration,
						OutboundBytes:    f.OutboundBytes,
						OutboundPackets:  f.OutboundPackets,
						OutboundDuration: f.OutboundDuration,
					}
					flowList = append(flowList, &ff)
				}

				flows.FLowsMap[ifaceName] = flowList
			}

			err := PostFlows(url, timeout, flows)
			if err != nil {
				log.Errorf("failed to post flows: %s - %s", time.Unix(flows.Start, 0), time.Unix(flows.End, 0))
			}
		}
	}
}

func PostFlows(url string, timeout int, flows Flows) (err error) {
	postJson, err := json.Marshal(flows)
	if err != nil {
		log.Errorf("failed to marshal flows to json with err: %s", err.Error())
		return
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(postJson))
	if err != nil {
		log.Errorf("failed to new http request with err: %s", err.Error())
		return
	}

	req.Close = false
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Errorf("http post failed with err: %s", err.Error())
		return
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode/100 != 2 {
		err = errors.New("response code is not 2xx but " + strconv.Itoa(resp.StatusCode))
		log.Errorf(err.Error())
		return
	}

	return
}
