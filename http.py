from base import SubStreamBase, StreamBase, ReContructBase, OneStreamBase
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
        self._flush_protcol()
        self.byte_io = BytesIO()
    
    def _flush_protcol(self):
        self.writer.put(self._file_name(), [self.byte_io.getvalue()])


class BytesStreamBase(OneStreamBase):
    
    def __init__(self, *args, **kwargs):
        super(BytesStreamBase, self).__init__(*args, **kwargs)
    
    def _build_new_stream(self, seq: int, next_seq: int) -> SubStreamBase:
        return BytesIOSubStreamBase(seq, next_seq, self.target_writer,
                             self._file_name(), self.timestamp, self.stream_count)


class HttpSubStreamBase(BytesIOSubStreamBase):
    
    def __init__(self, *args, **kwargs):
        super(HttpSubStreamBase, self).__init__(*args, **kwargs)
    
    def _request_bytes(self, req: Request) -> bytes:
        return bytes(req)
    
    def _response_bytes(self, resp: Response) -> bytes:
        return bytes(resp)
    
    def _flush_protcol(self):
        byte_value = self.byte_io.getvalue()
        try:
            self.writer(self._file_name(),
                        [self._request_bytes(Request(byte_value))])
            return
        except Exception:
            pass
        
        try:
            self.writer(self._file_name(),
                        [self._request_bytes(Response(byte_value))])
        except Exception:
            pass