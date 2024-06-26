from typing_extensions import Buffer
from base import StreamInterface, SubStreamBase, StreamBase, ReContructBase, OneStreamBase, TwoToOneStreamBase, ReConstructTwoToOne
from dpkt.ip import IP
from dpkt.tcp import TCP, TH_FIN, TH_SYN, TH_RST, TH_PUSH, TH_ACK, TH_URG, TH_ECE, TH_CWR, TH_NS
from dpkt.http import Request, Response
try:
    from BytesIO import BytesIO
except ImportError:
    from io import BytesIO


class BytesIOSubStreamBase(SubStreamBase):
    # TODO 待实现append_data、insert_data、extend等
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
        self._flush_protcol(self.byte_io)
        self.byte_io = BytesIO()

    def _flush_protcol(self, byte_io: BytesIO):
        self.writer.put(self._file_name(), [byte_io])


class BytesStreamBase(OneStreamBase):

    def __init__(self, *args, **kwargs):
        super(BytesStreamBase, self).__init__(*args, **kwargs)

    def _build_new_stream(self, seq: int, next_seq: int) -> SubStreamBase:
        return BytesIOSubStreamBase(seq, next_seq, self.target_writer,
                                    self._file_name(), self.timestamp, self.stream_count)


class TwoToOneBytesIOStreamBase(TwoToOneStreamBase):

    def __init__(self, *args, **kwargs):
        super(TwoToOneBytesIOStreamBase, self).__init__(*args, **kwargs)

    def _build_stream_base(self, pkt: TCP, src: Buffer, dst: Buffer) -> OneStreamBase:
        return BytesStreamBase(
            src, dst, pkt.sport, pkt.dport, writer=self.writer, timestamp=self.timestamp)


class BytesIOReConstructTwoToOne(ReConstructTwoToOne):

    def __init__(self, *args, **kwargs):
        super(BytesIOReConstructTwoToOne, self).__init__(*args, **kwargs)

    def _construct(self, src: Buffer, dst: Buffer,
                   sport: int, dport: int, timestamp: float) -> StreamInterface:
        return TwoToOneBytesIOStreamBase(src, dst,
                                         sport, dport, self.target_writer, timestamp)


class HttpSubStreamBase(BytesIOSubStreamBase):

    def __init__(self, *args, **kwargs):
        super(HttpSubStreamBase, self).__init__(*args, **kwargs)

    def _request_bytes(self, req: Request) -> bytes:
        return bytes(req)

    def _response_bytes(self, resp: Response) -> bytes:
        return bytes(resp)

    def _flush_protcol(self, byte_io: BytesIO):
        byte_value = byte_io.read()
        try:
            self.writer.put(self._file_name(), [
                            self._request_bytes(Request(byte_value))])
            return
        except Exception:
            pass

        try:
            self.writer.put(self._file_name(), [
                            self._response_bytes(Response(byte_value))])
        except Exception:
            pass


class HttpStreamBase(BytesStreamBase):

    def __init__(self, *args, **kwargs):
        super(HttpStreamBase, self).__init__(*args, **kwargs)

    def _build_new_stream(self, seq: int, next_seq: int) -> SubStreamBase:
        return HttpSubStreamBase(seq, next_seq, self.target_writer,
                                 self._file_name(), self.timestamp, self.stream_count)
