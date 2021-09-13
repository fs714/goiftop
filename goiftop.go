package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/fs714/goiftop/accounting"
	"github.com/fs714/goiftop/engine"
	"github.com/fs714/goiftop/notify"
	"github.com/fs714/goiftop/utils/config"
	"github.com/fs714/goiftop/utils/log"
	"github.com/fs714/goiftop/utils/version"
	"github.com/google/gopacket/pcap"
	"io"
	"net/http"
	"os"
	"os/signal"
	"runtime/pprof"
	"sync"
	"syscall"
	"time"
)

func init() {
	flag.StringVar(&config.IfaceListString, "i", "", "Interface name list seperated by comma for libpcap and afpacket, like eth0, eth1. This is used for libpcap and afpacket engine")
	flag.StringVar(&config.GroupListString, "g", "", "Nflog interface, group id and direction list seperated by comma, like eth0:2:in, eth0:3:out, eth1:4:int, eth1:5:out. This is used for nflog engine")
	flag.StringVar(&config.Engine, "engine", "libpcap", "Packet capture engine, could be libpcap, afpacket and nflog")
	flag.BoolVar(&config.IsDecodeL4, "l4", false, "Show transport layer flows")
	flag.Int64Var(&config.PrintInterval, "p", 0, "Interval to print flows, 0 means no print")
	flag.BoolVar(&config.IsEnableHttpSrv, "http", false, "Enable http server and ui")
	flag.StringVar(&config.HttpSrvAddr, "addr", "0.0.0.0", "Http server listening address")
	flag.StringVar(&config.HttpSrvPort, "port", "31415", "Http server listening port")
	flag.StringVar(&config.CpuProfile, "cpu_profile", "", "CPU profile file path")
	flag.BoolVar(&config.IsShowVersion, "v", false, "Show version")
	flag.Parse()

	err := log.SetLevel("info")
	if err != nil {
		fmt.Println("failed to set log level")
		os.Exit(1)
	}

	err = log.SetFormat("text")
	if err != nil {
		fmt.Println("failed to set log format")
		os.Exit(1)
	}

	log.SetOutput(os.Stdout)
}

func ArgsValidation() (err error) {
	if config.Engine != engine.LibPcapEngineName && config.Engine != engine.AfpacketEngineName &&
		config.Engine != engine.NflogEngineName {
		err = errors.New("invalid engine name: " + config.Engine)
		return
	}

	if config.Engine == engine.LibPcapEngineName || config.Engine == engine.AfpacketEngineName {
		if config.IfaceListString == "" {
			err = errors.New("no interface provided")
			return
		}
	}

	if config.Engine == engine.NflogEngineName {
		if config.GroupListString == "" {
			err = errors.New("no group id provided")
			return
		}
	}

	return
}

func main() {
	if config.IsShowVersion {
		fmt.Println(version.Version)
		os.Exit(0)
	}

	if os.Geteuid() != 0 {
		log.Errorln("must run as root")
		os.Exit(1)
	}

	err := ArgsValidation()
	if err != nil {
		log.Errorf("args validation failed with err: %s", err.Error())
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	ExitWG := &sync.WaitGroup{}

	if config.CpuProfile != "" {
		f, err := os.Create(config.CpuProfile)
		if err != nil {
			log.Errorf("failed to create file %s with err: %s", config.CpuProfile, err.Error())
			os.Exit(1)
		}

		err = pprof.StartCPUProfile(f)
		if err != nil {
			log.Errorf("failed to start cpu profile with err: %s", err.Error())
			os.Exit(1)
		}
	}

	if config.Engine == engine.NflogEngineName {
		err = config.ParseNflogConfig()
		if err != nil {
			log.Errorln(err.Error())
			os.Exit(1)
		}
	} else {
		config.ParseIfaces()
	}

	accounting.GlobalAcct = accounting.NewAccounting()
	accounting.GlobalAcct.SetRetention(300)
	for _, iface := range config.IfaceList {
		accounting.GlobalAcct.AddInterface(iface)
	}
	go func(ctx context.Context) {
		ExitWG.Add(1)
		defer ExitWG.Done()

		accounting.GlobalAcct.Start(ctx)
	}(ctx)

	var engineList []engine.PktCapEngine
	if config.Engine == engine.LibPcapEngineName {
		for _, iface := range config.IfaceList {
			eIn := engine.NewLibPcapEngine(iface, "", pcap.DirectionIn, 65535, config.IsDecodeL4)
			eOut := engine.NewLibPcapEngine(iface, "", pcap.DirectionOut, 65535, config.IsDecodeL4)
			engineList = append(engineList, eIn)
			engineList = append(engineList, eOut)
		}
	} else if config.Engine == engine.AfpacketEngineName {
		for _, iface := range config.IfaceList {
			eIn := engine.NewAfpacketEngine(iface, pcap.DirectionIn, config.IsDecodeL4)
			eOut := engine.NewAfpacketEngine(iface, pcap.DirectionOut, config.IsDecodeL4)
			engineList = append(engineList, eIn)
			engineList = append(engineList, eOut)
		}
	} else if config.Engine == engine.NflogEngineName {
		for _, nflogConf := range config.NflogConfigList {
			e := engine.NewNflogEngine(nflogConf.IfaceName, nflogConf.GroupId, nflogConf.Direction, config.IsDecodeL4)
			engineList = append(engineList, e)
		}
	} else {
		err = errors.New("invalid engine name: " + config.Engine)
		log.Errorln(err.Error())
		os.Exit(1)
	}

	for _, e := range engineList {
		go func(e engine.PktCapEngine) {
			err := e.StartEngine(accounting.GlobalAcct)
			if err != nil {
				log.Errorf("failed to start engine with err: %s", err.Error())
				os.Exit(1)
			}
		}(e)
	}

	if config.IsEnableHttpSrv {
		srv := &http.Server{
			Addr:           config.HttpSrvAddr + ":" + config.HttpSrvPort,
			ReadTimeout:    300 * time.Second,
			WriteTimeout:   300 * time.Second,
			MaxHeaderBytes: 1 << 20,
		}

		http.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "ok\n")
		})

		go func() {
			ExitWG.Add(1)
			defer ExitWG.Done()

			log.Infof("start http server on %s:%s", config.HttpSrvAddr, config.HttpSrvPort)
			_ = srv.ListenAndServe()
		}()

		go func(ctx context.Context) {
			ExitWG.Add(1)
			defer ExitWG.Done()

			select {
			case <-ctx.Done():
				cctx, ccancel := context.WithTimeout(context.Background(), 1*time.Second)
				defer ccancel()
				err := srv.Shutdown(cctx)
				if err != nil {
					log.Errorf("failed to close http server with err: %s", err.Error())
				}
				log.Infoln("http server exit")
			}
		}(ctx)
	}

	if config.PrintInterval > 0 {
		time.Sleep(1 * time.Second)
		go func(ctx context.Context) {
			ExitWG.Add(1)
			defer ExitWG.Done()

			notify.PrintNotifier(ctx, config.PrintInterval)
		}(ctx)
	}

	<-signalCh
	cancel()
	ExitWG.Wait()
	if config.CpuProfile != "" {
		pprof.StopCPUProfile()
		log.Infoln("cpu profile exit")
	}
}
