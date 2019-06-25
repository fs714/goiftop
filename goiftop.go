package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func init() {
	var version bool
	flag.BoolVar(&version, "v", false, "Version")
	flag.Parse()

	if version {
		fmt.Println(AppVersion)
		os.Exit(0)
	}
}

func main() {
	if os.Geteuid() != 0 {
		log.Fatalln("Must run as root")
	}

	ifs, err := net.Interfaces()
	if err != nil {
		log.Fatalf("Failed to get interfaces, err: %s\n", err.Error())
	}

	for _, i := range ifs {
		log.Printf("Found interface %s\n", i.Name)
	}

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGHUP, syscall.SIGINT)
	tick := time.Tick(time.Second * 1)

	var exit context.CancelFunc
	if len(ifs) > 0 {
		ctx, cancel := context.WithCancel(context.Background())
		exit = cancel
		go listenPacket(ifs[0].Name, ctx)
	} else {
		signalChan <- syscall.SIGINT
	}

	for {
		select {
		case <-tick:
			log.Println("Show Statistics")
		case <-signalChan:
			exit()
			goto END
		}
	}

END:
	log.Println("Exit...")
}

func listenPacket(iface string, ctx context.Context) {
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Failed to OpenLive by pcap, err: %s\n", err.Error())
	}

	err = handle.SetBPFFilter("udp || tcp")
	if err != nil {
		log.Fatalf("Failed to set BPF filter, err: %s\n", err.Error())
	}

	defer handle.Close()

	ps := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-ctx.Done():
			return
		case p := <-ps.Packets():
			log.Printf("Receive Packet: %v", p.Metadata().Length)
		}
	}
}
