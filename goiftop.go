package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var Stats = &Statistics{
	ifaces: make(map[string]*Iface),
}

type FlowSnapshot struct {
	Type               string
	SourceAddress      string
	DestinationAddress string
	UpStreamRate       int64
	DownStreamRate     int64
}

var L3FlowSnapshots = make([]*FlowSnapshot, 0, 0)
var L4FlowSnapshots = make([]*FlowSnapshot, 0, 0)

var ifaceName string
var duration int
var filter string
var enableLayer4 bool
var port int
var isShowVersion bool

func init() {
	flag.StringVar(&ifaceName, "i", "", "Interface name")
	flag.IntVar(&duration, "d", 1, "Throughput statistics duration")
	flag.StringVar(&filter, "f", "", "BPF filter")
	flag.BoolVar(&enableLayer4, "l4", false, "Show transport layer flows")
	flag.IntVar(&port, "p", 4096, "Http server listening port")
	flag.BoolVar(&isShowVersion, "v", false, "Version")
	flag.Parse()

	if isShowVersion {
		fmt.Println(AppVersion)
		os.Exit(0)
	}
}

func main() {
	go func() {
		log.Printf("Start HTTP Server on port %d\n", port)
		http.HandleFunc("/l3flow", L3FlowHandler)
		http.HandleFunc("/l4flow", L4FlowHandler)
		http.Handle("/", http.StripPrefix("/", http.FileServer(assetFS())))

		err := http.ListenAndServe(":"+strconv.Itoa(port), nil)
		if err != nil {
			fmt.Println("Failed to start http server with error: " + err.Error())
			os.Exit(0)
		}
	}()

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
			fmt.Println("------")
			updateL3FlowSnapshots()
			printFlowSnapshots(L3FlowSnapshots)
			if enableLayer4 {
				updateL4FlowSnapshots()
				printFlowSnapshots(L4FlowSnapshots)
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

func updateL3FlowSnapshots() {
	L3FlowSnapshots = make([]*FlowSnapshot, 0, 0)
	for _, v := range Stats.ifaces[ifaceName].L3Flows {
		if v.DeltaBytes[0] > 0 || v.DeltaBytes[1] > 0 {
			f := &FlowSnapshot{
				Type:               v.Type,
				SourceAddress:      v.Addr[0],
				DestinationAddress: v.Addr[1],
				UpStreamRate:       v.DeltaBytes[0] * 8 / int64(duration),
				DownStreamRate:     v.DeltaBytes[1] * 8 / int64(duration),
			}
			L3FlowSnapshots = append(L3FlowSnapshots, f)
		}
	}

	sort.Slice(L3FlowSnapshots, func(i, j int) bool {
		return math.Max(float64(L3FlowSnapshots[i].UpStreamRate), float64(L3FlowSnapshots[i].DownStreamRate)) >
			math.Max(float64(L3FlowSnapshots[j].UpStreamRate), float64(L3FlowSnapshots[j].DownStreamRate))
	})
}

func updateL4FlowSnapshots() {
	L4FlowSnapshots = make([]*FlowSnapshot, 0, 0)
	for _, v := range Stats.ifaces[ifaceName].L4Flows {
		if v.DeltaBytes[0] > 0 || v.DeltaBytes[1] > 0 {
			f := &FlowSnapshot{
				Type:               v.Protocol,
				SourceAddress:      v.Addr[0] + ":" + v.Port[0],
				DestinationAddress: v.Addr[1] + ":" + v.Port[1],
				UpStreamRate:       v.DeltaBytes[0] * 8 / int64(duration),
				DownStreamRate:     v.DeltaBytes[1] * 8 / int64(duration),
			}
			L4FlowSnapshots = append(L4FlowSnapshots, f)
		}
	}

	sort.Slice(L4FlowSnapshots, func(i, j int) bool {
		return math.Max(float64(L4FlowSnapshots[i].UpStreamRate), float64(L4FlowSnapshots[i].DownStreamRate)) >
			math.Max(float64(L4FlowSnapshots[j].UpStreamRate), float64(L4FlowSnapshots[j].DownStreamRate))
	})
}

func printFlowSnapshots(flowSnapshots []*FlowSnapshot) {
	for _, f := range flowSnapshots {
		var upRateStr, downRateStr string
		if f.UpStreamRate >= 1000000 {
			upRateStr = fmt.Sprintf("%.2fMbps", float64(f.UpStreamRate)/float64(1000000))
		} else if f.UpStreamRate >= 1000 && f.UpStreamRate < 1000000 {
			upRateStr = fmt.Sprintf("%.2fKbps", float64(f.UpStreamRate)/float64(1000))
		} else {
			upRateStr = fmt.Sprintf("%dbps", f.UpStreamRate)
		}

		if f.DownStreamRate >= 1000000 {
			downRateStr = fmt.Sprintf("%.2fMbps", float64(f.DownStreamRate)/float64(1000000))
		} else if f.DownStreamRate >= 1000 && f.DownStreamRate < 1000000 {
			downRateStr = fmt.Sprintf("%.2fKbps", float64(f.DownStreamRate)/float64(1000))
		} else {
			downRateStr = fmt.Sprintf("%dbps", f.DownStreamRate)
		}

		fmt.Printf("Type: %s, Src: %s, Dst: %s, Up: %s, Down: %s\n", f.Type, f.SourceAddress, f.DestinationAddress, upRateStr, downRateStr)
	}
}
