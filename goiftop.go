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
var filter string
var isTransport bool
var isShowVersion bool

func init() {
	flag.StringVar(&ifaceName, "i", "", "Interface name")
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
	tick := time.Tick(time.Second * 1)

	Stats.ifaces[ifaceName] = NewIface(ifaceName)
	ctx, cancel := context.WithCancel(context.Background())
	go listenPacket(ifaceName, ctx)

	for {
		select {
		case <-tick:
			log.Println()
			for k, v := range Stats.ifaces[ifaceName].NetworkFlows {
				log.Printf("%s %s %s %s %d %d\n", k, v.Type, v.Addr[0], v.Addr[1], v.TotalBytes[0], v.TotalBytes[1])
			}
			if isTransport {
				for k, v := range Stats.ifaces[ifaceName].TransportFlows {
					log.Printf("%s %s %s:%s %s:%s %d %d\n", k, v.Protocol, v.Addr[0], v.Port[0], v.Addr[1], v.Port[1], v.TotalBytes[0], v.TotalBytes[1])
				}
			}
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
			Stats.PacketHandler(ifaceName, p)
		}
	}
}
