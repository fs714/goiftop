package engine

const LibPcapEngineName = "libpcap"
const AfpacketEngineName = "afpacket"
const NflogEngineName = "nflog"

type PktCapEngine interface {
	StartEngine() error
}
