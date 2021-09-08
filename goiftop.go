package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/fs714/goiftop/utils/config"
	"github.com/fs714/goiftop/utils/version"
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
	flag.StringVar(&config.IfaceListString, "i", "", "Interface name list seperated by comma")
	flag.BoolVar(&config.IsDecodeL4, "l4", false, "Show transport layer flows")
	flag.IntVar(&config.PrintInterval, "p", 0, "Interval to print flows, 0 means no print")
	flag.BoolVar(&config.IsEnableHttpSrv, "http", false, "Enable http server and ui")
	flag.StringVar(&config.HttpSrvAddr, "addr", "0.0.0.0", "Http server listening address")
	flag.StringVar(&config.HttpSrvPort, "port", "31415", "Http server listening port")
	flag.StringVar(&config.CpuProfile, "cpu_profile", "", "CPU profile file path")
	flag.BoolVar(&config.IsShowVersion, "v", false, "Show version")
	flag.Parse()
}

func main() {
	if config.IsShowVersion {
		fmt.Println(version.Version)
		os.Exit(0)
	}

	if os.Geteuid() != 0 {
		fmt.Println("must run as root")
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	ExitWG := &sync.WaitGroup{}

	if config.CpuProfile != "" {
		f, err := os.Create(config.CpuProfile)
		if err != nil {
			fmt.Printf("failed to create file %s with err: %s\n", config.CpuProfile, err.Error())
			os.Exit(1)
		}

		err = pprof.StartCPUProfile(f)
		if err != nil {
			fmt.Printf("failed to start cpu profile with err: %s\n", err.Error())
			os.Exit(1)
		}
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

			fmt.Printf("start http server on %s:%s\n", config.HttpSrvAddr, config.HttpSrvPort)
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
					fmt.Printf("failed to close http server with err: %s\n", err.Error())
				}
				fmt.Println("http server exit")
			}
		}(ctx)
	}

	if config.PrintInterval > 0 {
		go func(ctx context.Context) {
			ExitWG.Add(1)
			defer ExitWG.Done()

			ticker := time.NewTicker(time.Duration(config.PrintInterval) * time.Second)
			for {
				select {
				case <-ctx.Done():
					fmt.Println("print flow exit")
					return
				case <-ticker.C:
					fmt.Println("flow info")
				}
			}
		}(ctx)
	}

	<-signalCh
	cancel()
	ExitWG.Wait()
	if config.CpuProfile != "" {
		pprof.StopCPUProfile()
		fmt.Println("cpu profile exit")
	}
}
