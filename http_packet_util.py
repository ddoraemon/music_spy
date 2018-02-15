# -*- coding: utf-8 -*-
# @Time    : 2018/2/15 下午3:48
# @Author  : Cloud
import urllib


class HttpPacketUtil(object):

    @classmethod
    def parse(cls, tcp_payload):
        lines = tcp_payload.split("\r\n")
        method = ""
        uri = ""
        headers = {}
        # 目前只解析http header部分，http payload再说吧
        try:
            base_info = lines[0].split(" ")
            method = base_info[0]
            uri = urllib.unquote(base_info[1])
            version = base_info[2]
            for line in lines[1:]:
                # 出现空行应该header部分结束了
                if line == "":
                    break
                kv = line.split(": ")
                if kv > 1:
                    key = kv[0].strip().lower()
                    value = ": ".join(kv[1:])
                    headers[key] = value
        except Exception as ex:
            print ex
        return {"method": method, "uri": uri, "headers": headers}

