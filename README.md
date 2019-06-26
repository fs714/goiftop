### 1. Introduction
This project is the iftop implementation by golang.

### 2. How to build
1. Install libpcap-dev firstly
```
# On Ubuntu
sudo apt-get install libpcap-dev
```

2. Build
```
make
```

### 3. Usage
```
Usage of ./bin/goiftop:
  -d int
        Throughput statistics duration (default 1)
  -f string
        BPF filter
  -i string
        Interface name
  -t    Show transport layer flows
  -v    Version
```
