package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/fs714/goiftop/utils/log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"math"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"syscall"
	"time"
)

var ifaceName string
var filter string
var enableLayer4 bool
var port int
var isShowVersion bool

func init() {
	flag.StringVar(&ifaceName, "i", "", "Interface name")
	flag.StringVar(&filter, "bpf", "", "BPF filter")
	flag.BoolVar(&enableLayer4, "l4", false, "Show transport layer flows")
	flag.IntVar(&port, "p", 16384, "Http server listening port")
	flag.BoolVar(&isShowVersion, "v", false, "Version")
	flag.Parse()

	if isShowVersion {
		fmt.Println(AppVersion)
		os.Exit(0)
	}
}

func main() {
	go func() {
		log.Infof("Start HTTP Server on port %d\n", port)
		http.HandleFunc("/l3flow", L3FlowHandler)
		http.HandleFunc("/l4flow", L4FlowHandler)
		http.Handle("/", http.StripPrefix("/", http.FileServer(assetFS())))

		err := http.ListenAndServe(":"+strconv.Itoa(port), nil)
		if err != nil {
			log.Errorf("Failed to start http server with error: %s\n" + err.Error())
			os.Exit(0)
		}
	}()

	if os.Geteuid() != 0 {
		log.Errorln("Must run as root")
	}

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGHUP, syscall.SIGINT)
	tickStatsDuration := time.Tick(time.Duration(1) * time.Second)

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
				fmt.Println()
				updateL4FlowSnapshots()
				printFlowSnapshots(L4FlowSnapshots)
			}
		case <-signalChan:
			cancel()
			goto END
		}
	}

END:
	log.Infoln("Exit...")
}

func listenPacket(ifaceName string, ctx context.Context) {
	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Errorf("Failed to OpenLive by pcap, err: %s\n", err.Error())
		os.Exit(0)
	}

	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Errorf("Failed to set BPF filter, err: %s\n", err.Error())
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
	Stats.ifaces[ifaceName].UpdateL3FlowQueue()
	for _, v := range Stats.ifaces[ifaceName].L3Flows {
		fss := v.GetSnapshot()
		if fss.DownStreamRate1+fss.UpStreamRate1+fss.DownStreamRate15+fss.UpStreamRate15+fss.DownStreamRate60+fss.UpStreamRate60 > 0 {
			L3FlowSnapshots = append(L3FlowSnapshots, fss)
		}
	}

	sort.Slice(L3FlowSnapshots, func(i, j int) bool {
		return math.Max(float64(L3FlowSnapshots[i].UpStreamRate1), float64(L3FlowSnapshots[i].DownStreamRate1)) >
			math.Max(float64(L3FlowSnapshots[j].UpStreamRate1), float64(L3FlowSnapshots[j].DownStreamRate1))
	})
}

func updateL4FlowSnapshots() {
	L4FlowSnapshots = make([]*FlowSnapshot, 0, 0)
	Stats.ifaces[ifaceName].UpdateL4FlowQueue()
	for _, v := range Stats.ifaces[ifaceName].L4Flows {
		fss := v.GetSnapshot()
		if fss.DownStreamRate1+fss.UpStreamRate1+fss.DownStreamRate15+fss.UpStreamRate15+fss.DownStreamRate60+fss.UpStreamRate60 > 0 {
			L4FlowSnapshots = append(L4FlowSnapshots, fss)
		}
	}

	sort.Slice(L4FlowSnapshots, func(i, j int) bool {
		return math.Max(float64(L4FlowSnapshots[i].UpStreamRate1), float64(L4FlowSnapshots[i].DownStreamRate1)) >
			math.Max(float64(L4FlowSnapshots[j].UpStreamRate1), float64(L4FlowSnapshots[j].DownStreamRate1))
	})
}

func printFlowSnapshots(flowSnapshots []*FlowSnapshot) {
	if len(flowSnapshots) > 0 {
		fmt.Printf("%-8s %-32s %-32s %-16s %-16s %-16s %-16s %-16s %-16s\n", "Protocol", "Src", "Dst", "Up1", "Down1", "Up15", "Down15", "Up60", "Down60")
	}

	for _, f := range flowSnapshots {
		u1 := rateToStr(f.UpStreamRate1)
		d1 := rateToStr(f.DownStreamRate1)
		u15 := rateToStr(f.UpStreamRate15)
		d15 := rateToStr(f.DownStreamRate15)
		u60 := rateToStr(f.UpStreamRate60)
		d60 := rateToStr(f.DownStreamRate60)
		fmt.Printf("%-8s %-32s %-32s %-16s %-16s %-16s %-16s %-16s %-16s\n", f.Protocol, f.SourceAddress, f.DestinationAddress, u1, d1, u15, d15, u60, d60)
	}
}

func rateToStr(rate int64) (rs string) {
	if rate >= 1000000 {
		rs = fmt.Sprintf("%.2f Mbps", float64(rate)/float64(1000000))
	} else if rate >= 1000 && rate < 1000000 {
		rs = fmt.Sprintf("%.2f Kbps", float64(rate)/float64(1000))
	} else {
		rs = fmt.Sprintf("%d bps", rate)
	}

	return
}
