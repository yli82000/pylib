
"""
Pcap文件头24B各字段说明：
Magic：        4B：0×1A 2B 3C 4D:用来识别文件自己和字节顺序。0xa1b2c3d4用来表示按照原来的顺序读取，0xd4c3b2a1表示下面的字节都要交换顺序读取。一般，我们使用0xa1b2c3d4
Major：        2B，0×02 00:当前文件主要的版本号
Minor：        2B，0×04 00当前文件次要的版本号
ThisZone：     4B 时区。GMT和本地时间的相差，用秒来表示。如果本地的时区是GMT，那么这个值就设置为0.这个值一般也设置为0 
SigFigs：      4B 时间戳的精度；全零
SnapLen：      4B最大的存储长度（该值设置所抓获的数据包的最大长度，如果所有数据包都要抓获，将该值设置为65535； 例如：想获取数据包的前64字节，可将该值设置为64）
LinkType：     4B链路类型
"""

# https://www.tcpdump.org/manpages/pcap-savefile.5.html
# https://www.tcpdump.org/linktypes.html

import struct

""" """
bytesorder = '@'


class PcapHead:
    
    """pcap文件头 24B"""
    _magic_number = None
    _version_major = None
    _version_minor = None
    _thiszone = None
    _sigfigs = None
    _snaplen = None
    _link_type = None
 
    def __init__(self, data):
        assert len(data) == 24
        self._magic_number = data[:4]
        if PcapHead.signature(self._magic_number) is False:
            raise Exception("不支持的文件格式")

        self._version_major, self._version_minor, self._thiszone, self._sigfigs, self._snaplen, self._link_type = struct.unpack(bytesorder + 'HHLLLL', bytes(data[4:]))
 
    def __str__(self):
        return "order:%s magor:%d minor:%d zone:%d sig:%d snap_len:%d type:%d" % (
            bytesorder, self._version_major, self._version_minor, self._thiszone, self._sigfigs, self._snaplen,
            self._link_type)
 

    @staticmethod
    def signature(data):
        
        sig = struct.unpack('@L', bytes(data))
        if sig == 0xa1b2c3d4:   # "big"
            bytesorder = '>'
            return True
        elif sig == 0xd4c3b2a1: # "little"
            bytesorder = '<'
            return True
        else:
            return False
 

 ###############################################################


class Pcap:
    """ .pcap parser """
    __head = None
    __ret = 0
 
    def parse(self, file, buffSize=2048):
        """
        解析pcap文件,返回值为一个生成器 yield
        :param file:缓冲文件大小
        :param buffSize:
        :return:返回一个生成器（用于处理大包）
        """
        assert file != ""
        _buff = BytesBuffer()
        _packet = None
        ret = 0
        with open(file, "rb") as o:
            ctx = None
            while 1:
                # 优先处理缓冲区数据(如果缓存数据超过了指定大小)
                bsize = len(_buff)
                if bsize > 0:
                    if bsize >= buffSize:
                        ctx = _buff.getvalue()
                    else:
                        _buff.write(o.read(buffSize))
                        ctx = _buff.getvalue()
                    _buff.clear()
                else:
                    ctx = o.read(buffSize)

                size = len(ctx)
                if size > 0:
                    if self.__head is None:
                        # 文件头占24字节
                        if size >= 24:
                            self.__head = PcapHead(ctx[:24])
                            size -= 24
                            ctx = ctx[24:]
                        else:
                            _buff.write(ctx)

                    # 分析包头(包头占16字节)
                    if size > 16:
                        if _packet is None:
                            _packet = Packet()
                            ctx, size = _packet.parse(ctx)
                            if _packet.finish():
                                yield _packet
                                ret += 1
                                _packet = None
                            if size > 0:
                                _buff.write(ctx)
                        else:
                            ctx, size = _packet.parse(ctx)
                            if _packet.finish():
                                yield _packet
                                ret += 1
                                _packet = None
                            if size > 0:
                                _buff.write(ctx)
                    else:
                        _buff.write(ctx)
                else:
                    break
            del ctx
        del _buff
        self.__ret = ret
 
    def __len__(self):
        return self.__ret
 
    @property
    def head(self):
        """获取包头,务必保证有调用parse后才能获得包头"""




class PacketHead:
    """包头 16B"""
    _ts_sec = 0
    _ts_usec = 0
    _incl_len = 0
    _orig_len = 0
 
    def __init__(self, data):
        self._ts_sec, self._ts_usec, self._incl_len, self._orig_len = struct.unpack(bytesorder+'LLLL', bytes(data))
 
    @property
    def sec(self):
        return self._ts_sec
 
    @property
    def usec(self):
        return self._ts_usec
 
    @property
    def incl(self):
        return self._incl_len
 
    @property
    def orig(self):
        return self._orig_len
 
    def __str__(self):
        return "PACKET sec:%d usec:%d incl len:%d orig len:%d" % (
            self._ts_sec, self._ts_usec, self._incl_len, self._incl_len)
 

class Packet:
    """数据包(未拆包)"""
    _head = None
    _buff = None
    name = "Packet"
 
    def __init__(self):
        super(ProcData, self).__init__()
        self._buff = BytesBuffer()
 
    def parse(self, data):
        """
        解析包数据
        :param data: 字节数据
        :return:    data,size
        """
        size = len(data)
        assert size > 0
        if self._head is None:
            self._head = PacketHead(data)
            size -= 16
            data = data[16:]
        if size > 0:
            _bs = len(self._buff)
            if _bs + size < self._head.incl:
                self._buff.write(data)
                size = 0
                data = None
            else:
                offset = self._head.incl - _bs
                self._buff.write(data[:offset])
                data = data[offset:]
                size -= offset
                assert len(data) == size
        return data, size
 
    def __del__(self):
        self._buff.close()
 
    @property
    def head(self):
        return self._head
 
    @property
    def data(self):
        return MAC(self._buff.getvalue(),None)
 
    def finish(self):
        return len(self._buff) == self._head.incl
