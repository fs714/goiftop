// Use cgo to interface with nflog
//
// Docs: http://www.netfilter.org/projects/libnetfilter_log/doxygen/index.html
//
// Debian packages needed:
// apt-get install linux-libc-dev libnetfilter-queue-dev libnetfilter-log-dev

package nflog

import (
	"log"
	"reflect"
	"syscall"
	"unsafe"
)

/*
#cgo LDFLAGS: -lnfnetlink -lnetfilter_log
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_log/libnetfilter_log.h>
#include <inttypes.h>

// A record of each packet
typedef struct {
	char *payload;
	int payload_len;
	u_int32_t seq;
} packet;

// Max number of packets to collect at once
#define MAX_PACKETS (16*1024)

// A load of packets with count
typedef struct {
	int index;
	packet pkt[MAX_PACKETS];
} packets;

// Process the incoming packet putting pointers to the data to be handled by Go
static int _processPacket(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg, struct nflog_data *nfd, void *data) {
	packets *ps = (packets *)data;
	if (ps->index >= MAX_PACKETS) {
		return 1;
	}
	packet *p = &ps->pkt[ps->index++];
	p->payload = 0;
	p->payload_len = nflog_get_payload(nfd, &p->payload);
	p->seq = 0;
	nflog_get_seq(nfd, &p->seq);
	return 0;
 }

// Register the callback - can't be done from Go
//
// We have to register a C function _processPacket
static int _callback_register(struct nflog_g_handle *gh, packets *data) {
	return nflog_callback_register(gh, _processPacket, data);
}

// A thin shim to call nflog_bind_group to work around the changes to
// the type of num
static struct nflog_g_handle *_nflog_bind_group(struct nflog_handle *h, int num) {
    return nflog_bind_group(h, num);
}
*/
import "C"

const (
	RecvBufferSize   = 4 * 1024 * 1024
	NflogBufferSize  = 128 * 1024 // Must be <= 128k (checked in kernel source)
	NfRecvBufferSize = 16 * 1024 * 1024
	NflogTimeout     = 100 // Timeout before sending data in 1/100th second
	MaxQueueLogs     = C.MAX_PACKETS - 1
)

type CallbackFunc func(data []byte) int

// NfLog
type NfLog struct {
	// Main nflog_handle
	h *C.struct_nflog_handle
	// File descriptor for socket operations
	fd C.int
	// Group handle
	gh *C.struct_nflog_g_handle
	// The multicast address
	McastGroup int
	// The next expected sequence number
	seq uint32
	// Errors
	errors int64
	// Quit the loop
	quit chan struct{}
	// Pointer to the packets
	packets *C.packets
	// Callback function
	fn CallbackFunc
}

// Create a new NfLog
//
// McastGroup is that specified in ip[6]tables
func NewNfLog(McastGroup int, fn CallbackFunc) *NfLog {
	h, err := C.nflog_open()
	if h == nil || err != nil {
		log.Fatalf("Failed to open NFLOG: %s", nflogError(err))
	}

	if rc, err := C.nflog_bind_pf(h, C.AF_INET); rc < 0 || err != nil {
		log.Fatalf("nflog_bind_pf failed: %s", nflogError(err))
	}

	nflog := &NfLog{
		h:          h,
		fd:         C.nflog_fd(h),
		McastGroup: McastGroup,
		quit:       make(chan struct{}),
		packets:    (*C.packets)(C.malloc(C.sizeof_packets)),
		fn:         fn,
	}

	nflog.makeGroup(McastGroup)
	// Start the background process
	go nflog.Loop()
	return nflog
}

// Connects to the group specified with the size
func (nflog *NfLog) makeGroup(group int) {
	gh, err := C._nflog_bind_group(nflog.h, C.int(group))
	if gh == nil || err != nil {
		log.Fatalf("nflog_bind_group failed: %s", nflogError(err))
	}
	nflog.gh = gh

	// Set the maximum amount of logs in buffer for this group
	if rc, err := C.nflog_set_qthresh(gh, MaxQueueLogs); rc < 0 || err != nil {
		log.Fatalf("nflog_set_qthresh failed: %s", nflogError(err))
	}

	// Set local sequence numbering to detect missing packets
	if rc, err := C.nflog_set_flags(gh, C.NFULNL_CFG_F_SEQ); rc < 0 || err != nil {
		log.Fatalf("nflog_set_flags failed: %s", nflogError(err))
	}

	// Set buffer size large
	if rc, err := C.nflog_set_nlbufsiz(gh, NflogBufferSize); rc < 0 || err != nil {
		log.Fatalf("nflog_set_nlbufsiz: %s", nflogError(err))
	}

	// Set recv buffer large - this produces ENOBUFS when too small
	if rc, err := C.nfnl_rcvbufsiz(C.nflog_nfnlh(nflog.h), NfRecvBufferSize); rc < 0 || err != nil {
		log.Fatalf("nfnl_rcvbufsiz: %s", err)
	} else {
		if rc < NfRecvBufferSize {
			log.Fatalf("nfnl_rcvbufsiz: Failed to set buffer to %d got %d", NfRecvBufferSize, rc)
		}
	}

	// Set timeout
	if rc, err := C.nflog_set_timeout(gh, NflogTimeout); rc < 0 || err != nil {
		log.Fatalf("nflog_set_timeout: %s", nflogError(err))
	}

	if rc, err := C.nflog_set_mode(gh, C.NFULNL_COPY_PACKET, 0xffff); rc < 0 || err != nil {
		log.Fatalf("nflog_set_mode failed: %s", nflogError(err))
	}

	// Register the callback now we are set up
	//
	// Note that we pass a block of memory allocated by C.malloc -
	// it isn't a good idea for C to hold pointers to go objects
	// which might move
	C._callback_register(gh, nflog.packets)
}

// Receive packets in a loop until quit
func (nflog *NfLog) Loop() {
	buflen := C.size_t(RecvBufferSize)
	pbuf := C.malloc(buflen)
	if pbuf == nil {
		log.Fatal("No memory for malloc")
	}
	defer C.free(pbuf)
	for {
		nr, err := C.recv(nflog.fd, pbuf, buflen, 0)
		select {
		case <-nflog.quit:
			return
		default:
		}

		if nr < 0 || err != nil {
			log.Printf("Recv failed: %s", err)
			nflog.errors++
		} else {
			// Handle messages in packet reusing memory
			nflog.packets.index = 0
			C.nflog_handle_packet(nflog.h, (*C.char)(pbuf), (C.int)(nr))

			n := int(nflog.packets.index)
			if n >= C.MAX_PACKETS {
				log.Printf("Packets buffer overflowed")
			}
			var packet []byte
			sliceHeader := (*reflect.SliceHeader)((unsafe.Pointer(&packet)))

			for i := 0; i < n; i++ {
				p := &nflog.packets.pkt[i]

				// Get the packet into a []byte
				// NB if the C data goes away then BAD things will happen!
				// So don't keep slices from this after returning from this function
				sliceHeader.Cap = int(p.payload_len)
				sliceHeader.Len = int(p.payload_len)
				sliceHeader.Data = uintptr(unsafe.Pointer(p.payload))

				// Process the packet
				seq := uint32(p.seq)
				if seq != 0 && seq != nflog.seq {
					nflog.errors++
					log.Printf("%d missing packets detected, %d to %d", seq-nflog.seq, seq, nflog.seq)
				}
				nflog.seq = seq + 1

				nflog.fn(packet)
			}
			sliceHeader = nil
			packet = nil
		}
	}
}

// Current nflog error
func nflogError(err error) error {
	if C.nflog_errno != 0 {
		return syscall.Errno(C.nflog_errno)
	}
	return err
}

// Close the NfLog down
func (nflog *NfLog) Close() {
	close(nflog.quit)
	// Sometimes hangs and doesn't seem to be necessary
	// if *Verbose {
	// 	log.Printf("Unbinding socket %d from group %d", nflog.fd, nflog.McastGroup)
	// }
	// if rc, err := C.nflog_unbind_group(nflog.gh); rc < 0 || err != nil {
	// 	log.Printf("nflog_unbind_group(%d) failed: %s", nflog.McastGroup, nflogError(err))
	// }
	if rc, err := C.nflog_close(nflog.h); rc < 0 || err != nil {
		log.Printf("nflog_close failed: %s", nflogError(nil))
	}
	C.free(unsafe.Pointer(nflog.packets))
}
