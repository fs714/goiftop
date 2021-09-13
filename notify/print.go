package notify

import (
	"context"
	"fmt"
	"github.com/fs714/goiftop/accounting"
	"github.com/fs714/goiftop/utils/config"
	"github.com/fs714/goiftop/utils/log"
	"github.com/olekukonko/tablewriter"
	"strconv"
	"strings"
	"time"
)

func PrintNotifier(ctx context.Context, duration int64) {
	ticker := time.NewTicker(time.Duration(duration) * time.Second)
	for {
		select {
		case <-ctx.Done():
			log.Infoln("print notifier exit")
			return
		case <-ticker.C:
			for ifaceName, flowColHist := range accounting.GlobalAcct.FlowAccd {
				fc, ts := flowColHist.AggregationByDuration(duration)

				start := time.Unix(ts.Start, 0).String()
				end := time.Unix(ts.End, 0).String()
				fmt.Printf("[%s %s - %s]\n", ifaceName, start, end)

				fmt.Println("- [Network Layer]")
				l3Buf := &strings.Builder{}
				l3Table := tablewriter.NewWriter(l3Buf)
				l3Table.SetHeader([]string{"Index", "SrcAddr", "DstAddr",
					"BytesIn", "PacketsIn", "DurationIn", "RateIn",
					"BytesOut", "PacketsOut", "DurationOut", "RateOut"})
				l3Table.SetAutoFormatHeaders(false)
				l3Table.SetRowLine(true)
				l3Table.SetAutoMergeCells(false)
				cnt := 0
				for _, f := range fc.L3FlowMap {
					inRateStr := "-"
					outRateStr := "-"
					if f.InboundDuration != 0 {
						inRate := float64(f.InboundBytes*8/f.InboundDuration/1000) / 1000
						inRateStr = fmt.Sprintf("%.2f", inRate)
					}
					if f.OutboundDuration != 0 {
						outRate := float64(f.OutboundBytes*8/f.OutboundDuration/1000) / 1000
						outRateStr = fmt.Sprintf("%.2f", outRate)
					}
					m := []string{
						strconv.Itoa(cnt),
						f.SrcAddr,
						f.DstAddr,
						strconv.FormatInt(f.InboundBytes, 10),
						strconv.FormatInt(f.InboundPackets, 10),
						strconv.FormatInt(f.InboundDuration, 10),
						inRateStr,
						strconv.FormatInt(f.OutboundBytes, 10),
						strconv.FormatInt(f.OutboundPackets, 10),
						strconv.FormatInt(f.OutboundDuration, 10),
						outRateStr,
					}
					l3Table.Append(m)
					cnt++
				}
				l3Table.Render()
				fmt.Println(l3Buf.String())

				if config.IsDecodeL4 {
					fmt.Println("- [Transport Layer]")
					l4Buf := &strings.Builder{}
					l4Table := tablewriter.NewWriter(l4Buf)
					l4Table.SetHeader([]string{"Index", "SrcAddr", "DstAddr", "SrcPort", "DstPort", "Protocol",
						"BytesIn", "PacketsIn", "DurationIn", "RateIn",
						"BytesOut", "PacketsOut", "DurationOut", "RateOut"})
					l4Table.SetAutoFormatHeaders(false)
					l4Table.SetRowLine(true)
					l4Table.SetAutoMergeCells(false)
					cnt := 0
					for _, f := range fc.L4FlowMap {
						inRateStr := "-"
						outRateStr := "-"
						if f.InboundDuration != 0 {
							inRate := float64(f.InboundBytes*8/f.InboundDuration/1000) / 1000
							inRateStr = fmt.Sprintf("%.2f", inRate)
						}
						if f.OutboundDuration != 0 {
							outRate := float64(f.OutboundBytes*8/f.OutboundDuration/1000) / 1000
							outRateStr = fmt.Sprintf("%.2f", outRate)
						}
						m := []string{
							strconv.Itoa(cnt),
							f.SrcAddr,
							f.DstAddr,
							strconv.Itoa(int(f.SrcPort)),
							strconv.Itoa(int(f.DstPort)),
							f.Protocol,
							strconv.FormatInt(f.InboundBytes, 10),
							strconv.FormatInt(f.InboundPackets, 10),
							strconv.FormatInt(f.InboundDuration, 10),
							inRateStr,
							strconv.FormatInt(f.OutboundBytes, 10),
							strconv.FormatInt(f.OutboundPackets, 10),
							strconv.FormatInt(f.OutboundDuration, 10),
							outRateStr,
						}
						l4Table.Append(m)
						cnt++
					}
					l4Table.Render()
					fmt.Println(l4Buf.String())
				}

				fmt.Println()
			}
		}
	}
}
