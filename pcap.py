# -*- coding: utf-8 -*-
# @Time    : 2018/2/15 下午4:01
# @Author  : Cloud
import os
from cffi import FFI
import threading


script_path = os.path.dirname(os.path.abspath(__file__))
lib_path = "%s/lib" % script_path
lib_name = "libpcap.1.8.1.dylib"
# 定义头文件和函数声明
DEFINES = """
#define    PCAP_ERRBUF_SIZE    256
typedef    unsigned int    u_int;
typedef    u_int    bpf_u_int32;
typedef    unsigned int    in_addr_t;
typedef    struct pcap pcap_t;
typedef    unsigned char    u_char;
typedef    long    __darwin_time_t;
typedef    int    __darwin_suseconds_t;
typedef    unsigned short    u_int16_t;
typedef    unsigned int    u_int32_t;


struct bpf_program
{
    u_int bf_len;
    struct bpf_insn *bf_insns;
};

//以太网头结构
typedef    struct
{
    u_char dstMacAddr[6];
    u_char srcMacAddr[6];
    u_int16_t etherType;
} ETHERNET_HEADER;

//IP协议头
typedef    struct
{
    u_int headerLen:4;
    u_int version:4;
    u_char tos;
    u_int16_t totalLen;
    u_int16_t identi;
    u_int16_t flags;
    u_char ttl;
    u_char protocol;
    u_int16_t checksum;
    u_char srcIpAddr[4];
    u_char dstIpAddr[4];
} IP_HEADER;

//TCP协议头
typedef    struct
{
    u_int16_t srcPort;
    u_int16_t dstPort;
    u_int32_t seqNumber;
    u_int32_t ackNumber;
    u_int16_t rev:4;
    u_int16_t headerLen:4;
    u_int16_t flags:8;
    u_int16_t window;
    u_int16_t checksum;
    u_int16_t urgent;
} TCP_HEADER;

struct timeval
{
    __darwin_time_t         tv_sec;
    __darwin_suseconds_t    tv_usec;
};

struct pcap_pkthdr
{
    struct timeval ts;
    bpf_u_int32 caplen;
    bpf_u_int32 len;
};

struct in_addr
{
    in_addr_t s_addr;
};


//定义函数
char    *inet_ntoa(struct in_addr);
const    char *pcap_lib_version(void);
char    *pcap_lookupdev(char *);
int      pcap_lookupnet(const char *, bpf_u_int32 *, bpf_u_int32 *, char *);
pcap_t  *pcap_open_live(const char *, int, int, int, char *);
typedef  void (*pcap_handler)(u_char *, const struct pcap_pkthdr *, const u_char *);
int      pcap_loop(pcap_t *, int, pcap_handler, u_char *);
int      pcap_compile(pcap_t *, struct bpf_program *, const char *, int, bpf_u_int32);
void     pcap_breakloop(pcap_t *);
char    *pcap_geterr(pcap_t *);
int      pcap_setfilter(pcap_t *, struct bpf_program *);
void	 pcap_close(pcap_t *);
"""

ffi = FFI()
ffi.cdef(DEFINES)


class CapThread(threading.Thread):
    def __init__(self, lib, phandle, callback, params):
        super(CapThread, self).__init__()
        self.lib = lib
        self.phandle = phandle
        self.callback = callback
        self.params = params

    def run(self):
        self.lib.pcap_loop(self.phandle, -1, self.callback, self.params)
        print "cap thread over !!!"


class Pcap(object):

    def __init__(self):
        self.lib = ffi.dlopen("%s/%s" % (lib_path, lib_name))
        self.pcap_error_buffer = ffi.new("char[PCAP_ERRBUF_SIZE]")
        print ffi.string(self.lib.pcap_lib_version())
        self.phandle = None

    def init_pcap(self):
        self.dev_name = self.lib.pcap_lookupdev(self.pcap_error_buffer)
        if self.dev_name == ffi.NULL:
            raise Exception("Can not found and network card: %s" % ffi.string(self.pcap_error_buffer))
        else:
            print "use device %s" % ffi.string(self.dev_name)
        self.netp = ffi.new("bpf_u_int32 *")
        self.maskp = ffi.new("bpf_u_int32 *")
        self.phandle = self.lib.pcap_open_live(self.dev_name, 65535, 0, 500, self.pcap_error_buffer)
        if self.phandle == ffi.NULL:
            raise Exception("init pcap fail: %s" % ffi.string(self.pcap_error_buffer))

        result = self.lib.pcap_lookupnet(self.dev_name, self.netp, self.maskp, self.pcap_error_buffer)
        if result == -1:
            raise Exception("lookup net fail: %s" % ffi.string(self.pcap_error_buffer))

    def set_filter(self, string):
        fcode = ffi.new("struct bpf_program *")
        result = self.lib.pcap_compile(self.phandle, fcode, string, 0, self.maskp[0])
        if result == -1:
            raise Exception("pcap_compile error: %s" % ffi.string(self.lib.pcap_geterr(self.phandle)))
        result = self.lib.pcap_setfilter(self.phandle, fcode)
        if result == -1:
            raise Exception("pcap_setfilter error: %s" % ffi.string(self.lib.pcap_geterr(self.phandle)))

    def start_cap(self, callback):
        self.callback = callback
        self.cap_thread = CapThread(self.lib, self.phandle, self.callback, ffi.NULL)
        self.cap_thread.setDaemon(True)
        self.cap_thread.start()

    def stop_cap(self):
        self.lib.pcap_breakloop(self.phandle)
        self.cap_thread.join()

    def close_pcap(self):
        self.lib.pcap_close(self.phandle)
