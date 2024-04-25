from base import SubStreamBase, StreamBase, ReContructBase
from dpkt.ip import IP
from dpkt.tcp import TCP, TH_FIN, TH_SYN, TH_RST, TH_PUSH, TH_ACK, TH_URG, TH_ECE, TH_CWR, TH_NS
from dpkt.http import Request, Response
try:
    from BytesIO import BytesIO
except ImportError:
    from io import BytesIO


class BytesIOSubStreamBase(SubStreamBase):
    
    def __init__(self, *args, **kwargs):
        super(BytesIOSubStreamBase, self).__init__(*args, **kwargs)
        self.byte_io = BytesIO()
        self.is_request = None
    
    def _append_pkt(self, pkt: TCP):
        self.byte_io.write(pkt.data)
    
    def _insert_pkt(self, pkt: TCP):
        new_io = BytesIO()
        new_io.write(pkt.data)
        new_io.write(self.byte_io.getvalue())
        self.byte_io = new_io
    
    def _extend(self, stream: object):
        self.byte_io.write(stream.byte_io.getvalue())
    
    def _flush(self):
        self.writer.put(self._file_name(), [self.byte_io.getvalue()])
    