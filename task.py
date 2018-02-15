# -*- coding: utf-8 -*-
# @Time    : 2018/2/15 下午4:55
# @Author  : Cloud

from pcap import ffi, Pcap
import socket
import time
from utils import Utils
import threading
import httplib
from http_packet_util import HttpPacketUtil
import os


script_path = os.path.dirname(os.path.abspath(__file__))


def is_http(tcp_payload, payload_len):
    if payload_len <= 0:
        return False

    payload_string = ffi.string(tcp_payload, payload_len)
    if "HTTP/1." in payload_string:
        return True
    else:
        return False


def is_play_url(tcp_payload, payload_len):
    keyword_list = [
        {"op": "find", "keyword": ".m4a?", "not_exp": -1},
        {"op": "find", "keyword": ".mp3?", "not_exp": -1},
        {"op": "endswith", "keyword": ".mp3", "not_exp": False},
    ]
    result = False
    data_string = ffi.string(tcp_payload, payload_len)
    first_line = data_string.split("\r\n")[0]
    url = first_line.split(" ")[1]
    for keyword in keyword_list:
        method = getattr(url, keyword.get("op"))
        result = method(keyword.get("keyword"))
        if result != keyword.get("not_exp"):
            return True

    return result


def print_payload_as_string(tcp_payload, payload_len):
    print ffi.string(tcp_payload, payload_len)


class BackgroundDownload(threading.Thread):
    def __init__(self, host, url, method, music_folder):
        super(BackgroundDownload, self).__init__()
        self.host = host
        self.url = url
        self.method = method
        self.music_folder = music_folder

    def run(self):
        print "开始下载"
        file_path = self.url.split("?")[0]
        file_name = file_path.split("/")[-1]
        conn = httplib.HTTPConnection(self.host)
        conn.request(self.method, self.url, headers={"Referer": "http://www.cloud.com"})
        res = conn.getresponse()
        data = res.read()
        conn.close()
        if not os.path.exists(self.music_folder):
            os.makedirs(self.music_folder)
        with open("%s/%s" % (self.music_folder, file_name), "wb") as fp:
            fp.write(data)
        print "下载结束"



def get_local_ip():
    hostname = socket.gethostname()
    name = socket.getfqdn(socket.gethostname())
    ip = socket.gethostbyname(hostname)
    print '本机ip为 %s' % ip
    return ip


@ffi.callback("void(u_char *, const struct pcap_pkthdr *, const u_char *)")
def callback(user, header, pkt_data):
    ether_header = ffi.cast("ETHERNET_HEADER *", pkt_data)
    if header.len > ffi.sizeof("ETHERNET_HEADER"):
        ip_header = ffi.cast("IP_HEADER *", pkt_data + ffi.sizeof("ETHERNET_HEADER"))
        if ip_header.protocol != 6:
            # 不处理非tcp包
            return
        ip_length = Utils.swap16(ip_header.totalLen)
        tcp_header = ffi.cast("TCP_HEADER *", ip_header + 1)
        tcp_header_len = tcp_header.headerLen * 4
        tcp_payload = ffi.cast("u_char *", tcp_header) + tcp_header_len
        payload_len = ip_length - ffi.sizeof("IP_HEADER") - tcp_header_len


        http_request = is_http(tcp_payload, payload_len)
        if http_request and is_play_url(tcp_payload, payload_len):
            request_info = HttpPacketUtil.parse(ffi.string(tcp_payload, payload_len))
            print_payload_as_string(tcp_payload, payload_len)
            print "dst ip: %s.%s.%s.%s" % (ip_header.dstIpAddr[0], ip_header.dstIpAddr[1], ip_header.dstIpAddr[2], ip_header.dstIpAddr[3])
            if ("referer" not in request_info["headers"]) or (request_info["headers"]["referer"] != "http://www.cloud.com"):
                music_folder = "%s/music" % script_path
                BackgroundDownload(request_info["headers"]["host"], request_info["uri"], request_info["method"], music_folder).start()



if __name__ == "__main__":
    cap = Pcap()
    cap.init_pcap()
    local_ip = get_local_ip()
    # 只抓发出去的tcp包
    cap.set_filter("tcp and (dst host not %s)" % local_ip)
    cap.start_cap(callback)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt as KI:
        cap.stop_cap()
        cap.close_pcap()
        print "结束监听"
