package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var Stats = &Statistics{
	ifaces: make(map[string]*Iface),
}

var ifaceName string
var duration int
var filter string
var isTransport bool
var isShowVersion bool

func init() {
	flag.StringVar(&ifaceName, "i", "", "Interface name")
	flag.IntVar(&duration, "d", 1, "Throughput statistics duration")
	flag.StringVar(&filter, "f", "", "BPF filter")
	flag.BoolVar(&isTransport, "t", false, "Show transport layer flows")
	flag.BoolVar(&isShowVersion, "v", false, "Version")
	flag.Parse()

	if isShowVersion {
		fmt.Println(AppVersion)
		os.Exit(0)
	}
}

func main() {
	if os.Geteuid() != 0 {
		log.Fatalln("Must run as root")
	}

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGHUP, syscall.SIGINT)
	tickStatsDuration := time.Tick(time.Second * time.Duration(duration))

	Stats.ifaces[ifaceName] = NewIface(ifaceName)
	ctx, cancel := context.WithCancel(context.Background())
	go listenPacket(ifaceName, ctx)

	for {
		select {
		case <-tickStatsDuration:
			fmt.Println()
			for _, v := range Stats.ifaces[ifaceName].NetworkFlows {
				printRate(v.Type, v.Addr[0], v.Addr[1], v.DeltaBytes[0], v.DeltaBytes[1])
			}
			if isTransport {
				for _, v := range Stats.ifaces[ifaceName].TransportFlows {
					printRate(v.Protocol, v.Addr[0]+":"+v.Port[0], v.Addr[1]+":"+v.Port[1], v.DeltaBytes[0], v.DeltaBytes[1])
				}
			}

			Stats.ifaces[ifaceName].ResetDeltaBytes()
		case <-signalChan:
			cancel()
			goto END
		}
	}

END:
	log.Println("Exit...")
}

func listenPacket(ifaceName string, ctx context.Context) {
	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Failed to OpenLive by pcap, err: %s\n", err.Error())
		os.Exit(0)
	}

	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatalf("Failed to set BPF filter, err: %s\n", err.Error())
		os.Exit(0)
	}

	defer handle.Close()

	ps := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-ctx.Done():
			return
		case p := <-ps.Packets():
			go Stats.PacketHandler(ifaceName, p)
		}
	}
}

func printRate(flowType string, srcAddr string, dstAddr string, upDeltaBytes int64, downDeltaBytes int64) {
	if upDeltaBytes > 0 || downDeltaBytes > 0 {
		upRate := upDeltaBytes * 8 / int64(duration)
		downRate := downDeltaBytes * 8 / int64(duration)

		var upRateStr, downRateStr string
		if upRate >= 1000000 {
			upRateStr = fmt.Sprintf("%.2fMbps", float64(upRate)/float64(1000000))
		} else if upRate >= 1000 && upRate < 1000000 {
			upRateStr = fmt.Sprintf("%.2fKbps", float64(upRate)/float64(1000))
		} else {
			upRateStr = fmt.Sprintf("%dbps", upRate)
		}

		if downRate >= 1000000 {
			downRateStr = fmt.Sprintf("%.2fMbps", float64(downRate)/float64(1000000))
		} else if upRate >= 1000 && upRate < 1000000 {
			downRateStr = fmt.Sprintf("%.2fKbps", float64(downRate)/float64(1000))
		} else {
			downRateStr = fmt.Sprintf("%dbps", downRate)
		}

		fmt.Printf("Type: %s, Src: %s, Dst: %s, Up: %s, Down: %s\n", flowType, srcAddr, dstAddr, upRateStr, downRateStr)
	}
}
