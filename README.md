### 1. Introduction
This project is the iftop implementation by golang.

### 2. How to build
- Install libpcap-dev firstly
```
# On Ubuntu
sudo apt-get install libpcap-dev
```

- Install dependancy
```
go get github.com/jteeuwen/go-bindata/...
go get github.com/elazarl/go-bindata-assetfs/...
go mod tidy
```

- Build
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
  -l4
        Show transport layer flows
  -p int
        Http server listening port (default 4096)
  -v    Version
```

### 4. Http GUI
- http://ip:4096

### 5. Http API
- http://ip:4096/l3flow
- http://ip:4096/l4flow
