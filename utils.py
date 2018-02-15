# -*- coding: utf-8 -*-
# @Time    : 2018/2/15 下午4:56
# @Author  : Cloud


class Utils(object):

    @classmethod
    def swap16(cls, int16):
        result = 0
        result += (int16 & 0xFF00) >> 8
        result += (int16 & 0x00FF) << 8
        return result