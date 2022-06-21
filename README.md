### 1. Introduction
This project is the iftop implementation by golang.

### 2. How to build
- Install Required libs
```
# On Ubuntu
sudo apt-get install linux-libc-dev libpcap-dev libnetfilter-queue-dev libnetfilter-log-dev
```

- Build
```
make
```

### 3. Usage
```
Usage of ./bin/goiftop:
  -addr string
        Http server listening address (default "0.0.0.0")
  -engine string
        Packet capture engine, could be libpcap, afpacket and nflog (default "libpcap")
  -http
        Enable http server and ui
  -i string
        Interface name list seperated by comma for libpcap and afpacket, like eth0, eth1. This is used for libpcap and afpacket engine
  -l4
        Show transport layer flows
  -nflog string
        Nflog interface, group id and direction list seperated by comma, like eth0:2:in, eth0:3:out, eth1:4:int, eth1:5:out. This is used for nflog engine
  -port string
        Http server listening port (default "31415")
  -print.enable
        enable print notifier
  -print.interval int
        Interval to print flows (default 2)
  -profiling
        Enable profiling by http
  -v    Show version
  -webhook.enable
        enable webhook notifier
  -webhook.interval int
        Interval for webhook to send out flows (default 15)
  -webhook.node_id string
        Node identification for webhook
  -webhook.node_oam_addr string
        node oam address for webhook
  -webhook.post_timeout int
        Post timeout for webhook to send out flows (default 2)
  -webhook.url string
        webhokk url
```

