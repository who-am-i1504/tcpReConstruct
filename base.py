import queue
import dpkt
from typing import Tuple
from collections import defaultdict
from dpkt.ip import IP
from dpkt.tcp import TCP, TH_FIN, TH_SYN, TH_RST, TH_PUSH, TH_ACK, TH_URG, TH_ECE, TH_CWR, TH_NS
from dpkt.dpkt import NeedData
from dpkt.pcap import Reader as PReader
from dpkt.pcapng import Reader as PGReader
from dpkt.ethernet import Ethernet
from dpkt.sll import SLL
from threading import Thread
from socket import inet_ntop
from socket import AF_INET
from socket import AF_INET6
import time
import concurrent.futures
import threading
from typing_extensions import Buffer, LiteralString, TypeAlias
import os
from writer import NIOWriter


def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return inet_ntop(AF_INET, inet)
    except ValueError:
        return inet_ntop(AF_INET6, inet)


def four_meta_item_str(src: Buffer, sport: int, dst: Buffer, dport: int) -> str:
    return f"{inet_to_str(src)}:{sport}_{inet_to_str(dst)}:{dport}"


def four_meta_file_name(src: Buffer, sport: int, dst: Buffer, dport: int) -> str:
    return f'{inet_to_str(src)}-{sport}_{inet_to_str(dst)}-{dport}'


class SubStreamBase:

    def __init__(self, head_seq: int, next_seq: int, writer: NIOWriter,
                 abs_path: str, timestamp: float = time.time(), id_number: int = 0):
        self.head_seq = head_seq
        self.next_seq = next_seq
        self.datas = []
        self.writer = writer
        self.timestamp = timestamp
        self.abs_path = abs_path
        self.id_number = id_number

    def is_head_for_seq(self, seq: int) -> bool:
        return self.head_seq == seq

    def is_next_for_seq(self, seq: int) -> bool:
        return self.next_seq == seq

    def is_euqals_for_head_and_next(self) -> bool:
        return self.head_seq == self.next_seq

    def append_pkt(self, pkt: TCP, next_seq: int):
        self._append_pkt(pkt)
        self.next_seq = next_seq

    def _append_pkt(self, pkt: TCP):
        self.datas.append(pkt.data)

    def insert_pkt(self, pkt: TCP):
        self._insert_pkt(pkt)
        self.head_seq = pkt.seq

    def _insert_pkt(self, pkt: TCP):
        self.datas.insert(0, pkt.data)

    def append(self, stream: object):
        self._extend(stream)
        self.head_seq = min(self.head_seq, stream.head_seq)
        self.next_seq = max(self.next_seq, stream.next_seq)

    def _extend(self, stream: object):
        self.datas.extend(stream.datas)

    def flush(self):
        if self.writer is None:
            return
        self._flush()

    def _file_name(self):
        return f'{self.timestamp}_{self.abs_path}_{self.id_number}'

    def _flush(self):
        self.writer.put(self._file_name(), self.datas)
        self.datas = []


class StreamInterface:
    def __init__(self, *args, **kwargs):
        pass

    def append_pkt(self, pkt: TCP, src: Buffer, dst: Buffer) -> bool:
        pass

    def flush(self):
        pass


class StreamBase(StreamInterface):
    def __init__(self, src: Buffer, dst: Buffer,
                 sport: int, dport: int, writer: NIOWriter = None, timestamp: float = time.time()):
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport
        self.dic = {}
        # self.seq_packet = {}
        # self.ack_packet = {}
        self.stream_count = 0
        self.target_writer = writer
        self.start_output = False
        self.timestamp = timestamp
        self.min_seq_dic = {}

    def _append_file(self, stream: SubStreamBase):
        stream.flush()

    def flush(self):
        for seq, seq_stream in self.min_seq_dic.items():
            seq_stream.flush()

    def _file_name(self):
        return four_meta_file_name(self.src, self.sport, self.dst, self.dport)

    def append_pkt(self, pkt: TCP, src: Buffer, dst: Buffer) -> bool:
        seq = pkt.seq
        next_seq = pkt.seq + len(pkt.data)
        if (pkt.flags & TH_SYN) == TH_SYN:
            next_seq += 1
        if seq not in self.dic:
            self._insert_in_stream(seq, next_seq, pkt)
            return False
        pkts = self.dic[seq]
        if pkts.is_head_for_seq(seq) and not pkts.is_euqals_for_head_and_next():
            # TODO 重传判断，待完善
            return self._fin_deal(pkts=None, pkt=pkt)

        self._construct_mult_stream(seq, next_seq, pkt)
        return self._fin_deal(pkts, pkt)

    def _fin_deal(self, pkts: SubStreamBase, pkt: TCP) -> bool:
        if (pkt.flags & TH_FIN) == TH_FIN:
            # 刷新文件
            if pkts is not None:
                self._append_file(pkts)
            return True
        return False

    def _construct_mult_stream(self, seq: int, next_seq: int, pkt: TCP):
        # 清理seqkey
        seq_stream = self.dic.pop(seq)
        seq_stream.append_pkt(pkt, next_seq)
        next_seq_key = next_seq
        while next_seq_key in self.dic:
            self.min_seq_dic.pop(next_seq_key, None)
            cur = self.dic.pop(next_seq_key)
            if cur.is_head_for_seq(next_seq_key):
                next_seq_key = cur.next_seq
                seq_stream.append(cur)
            else:
                self.dic.pop(cur.head_seq, None)
                break

        self.dic[seq_stream.head_seq] = seq_stream
        self.dic[seq_stream.next_seq] = seq_stream
        self.min_seq_dic[seq_stream.head_seq] = seq_stream

    def _insert_in_stream(self, seq: int, next_seq: int, pkt: TCP):
        if next_seq not in self.dic:
            self.__build_new_stream(seq, next_seq, pkt)
            return
        if self.dic[next_seq].is_next_for_seq(next_seq):
            return
        pkts = self.dic.pop(next_seq)
        self.min_seq_dic.pop(next_seq)
        pkts.insert_pkt(pkt)
        self.dic[seq] = pkts
        self.min_seq_dic[seq] = pkts

    def __build_new_stream(self, seq: int, next_seq: int, pkt: TCP):
        self.stream_count += 1
        new_stream = self._build_new_stream(seq, next_seq)
        self.dic[seq] = new_stream
        self.dic[next_seq] = new_stream
        new_stream.append_pkt(pkt, next_seq)
        self.min_seq_dic[seq] = new_stream

    def _build_new_stream(self, seq: int, next_seq: int) -> SubStreamBase:
        return SubStreamBase(seq, next_seq, self.target_writer,
                             self._file_name(), self.timestamp, self.stream_count)

    def __hash__(self) -> int:
        return hash(self.src) ^ hash(self.dst) ^ hash(self.sport) ^ hash(self.dport)

    def __eq__(self, value: object) -> bool:
        return self.src == value.src and self.dst == value.dst and self.sport == value.sport and self.dport == value.dport


class ReContructBase:

    def __init__(self, abs_path: str, pcap_name: str, target_path: str = 'rebuild'):
        self.seq_pqueue = queue.PriorityQueue()
        self.stream_dic = defaultdict(None)
        self.target_writer = NIOWriter(
            dir=self.__set_target_path(abs_path, target_path))
        self.write_thread = Thread(target=self.target_writer.start_loop)
        self.write_thread.start()
        self.pcap_file = os.path.join(abs_path, pcap_name)
        self.lock = threading.Lock()

    def __set_target_path(self, abs_path: str, target_path: str) -> str:
        abs_target_path = os.path.join(abs_path, target_path)
        if os.path.exists(abs_target_path):
            return abs_target_path
        os.mkdir(abs_target_path)
        return abs_target_path

    def _getReader(self, f):
        # try:
        #     return PReader(f)
        # except Exception:
        #     pass

        try:
            return PGReader(f)
        except Exception:
            return None

    def _construct_for_multi_process(self, timestamp: float, pkt: dpkt.Packet) -> bool:
        eth = self.__parse_eth(pkt)
        if eth is None:
            return False
        tcp, src, dst = self.__upack_tcp(eth)
        if tcp is None:
            return False
        self.lock.acquire()
        try:
            self.__construct(tcp, src, dst, timestamp)
        finally:
            self.lock.release()
        return True

    def construct(self):
        with open(self.pcap_file, 'rb') as f:
            pcap_reader = self._getReader(f)
            result = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
                result.extend(pool.submit(
                    self._construct_for_multi_process,
                    timestamp, pkt) for timestamp, pkt in pcap_reader)
                for res in concurrent.futures.as_completed(result):
                    res.result()
        for stream_value in self.stream_dic.values():
            stream_value.flush()

        while self.write_thread.is_alive():
            self.target_writer.quit()
            time.sleep(1)

    def __parse_eth(self, pkt: dpkt.Packet) -> Ethernet:
        try:
            return Ethernet(pkt)
        except NeedData:
            pass
        try:
            return SLL(pkt)
        except NeedData:
            return None

    def __upack_tcp(self, pkt: Ethernet) -> Tuple[TCP, Buffer, Buffer]:
        if not isinstance(pkt.data, IP):
            return None, None, None
        ip = pkt.data
        if not isinstance(ip.data, TCP):
            return None, None, None
        return ip.data, ip.src, ip.dst

    def _hash_for_four_meta(self, src: Buffer, sport: int, dst: Buffer, dport: int):
        return four_meta_item_str(src, sport, dst, dport)

    def __construct(self, pkt: TCP, src: Buffer, dst: Buffer, ts: float):
        sport = pkt.sport
        dport = pkt.dport
        key = self._hash_for_four_meta(src, sport, dst, dport)
        if key not in self.stream_dic:
            self.stream_dic[key] = self._construct(src, dst, sport, dport, ts)

        if self.stream_dic[key].append_pkt(pkt, src, dst):
            self.stream_dic.pop(key)

    def _construct(self, src: Buffer, dst: Buffer,
                   sport: int, dport: int, ts: float) -> StreamInterface:
        return StreamBase(src, dst, sport, dport,
                          writer=self.target_writer, timestamp=ts)


class TwoToOneMetaItem:
    def __init__(self, src: Buffer, sport: int, dst: Buffer, dport: int):
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport

    def __hash__(self) -> int:
        return hash(self.src) ^ hash(self.dst) ^ hash(self.sport) ^ hash(self.dport)

    def _eq_ip(self, source: Buffer, target: Buffer) -> bool:
        return inet_to_str(source) == inet_to_str(target)

    def _actual_eq(self, value: object) -> bool:
        return self.sport == value.sport and self.dport == value.dport and self._eq_ip(self.src, value.src) and self._eq_ip(self.dst, value.dst)

    def _reverse_eq(self, value: object) -> bool:
        return self.sport == value.dport and self.dport == value.sport and self._eq_ip(self.src, value.dst) and self._eq_ip(self.dst, value.src)

    def __eq__(self, value: object) -> bool:
        return self._actual_eq(value) or self._reverse_eq(value)

    def __str__(self) -> str:
        return four_meta_file_name(self.src, self.sport, self.dst, self.dport)


class OneStreamBase(StreamBase):

    def __init__(self, *args, **kwargs):
        super(OneStreamBase, self).__init__(*args, **kwargs)

    def set_file_name(self, file_name: str):
        self.file_name = file_name

    def _file_name(self):
        return self.file_name

    def flush_seq(self, ack: int):
        if ack not in self.dic:
            return
        self.dic[ack].flush()


class TwoToOneStreamBase(StreamInterface):

    def __init__(self, src: Buffer, dst: Buffer, sport: int, dport: int, writer: NIOWriter = None, timestamp: float = time.time()):
        self.meta_item = TwoToOneMetaItem(src, sport, dst, dport)
        self.stream_dic = defaultdict(None)
        self.writer = writer
        self.timestamp = timestamp

    def append_pkt(self, pkt: TCP, src: Buffer, dst: Buffer) -> bool:
        key = four_meta_item_str(src, pkt.sport, dst, pkt.dport)
        reverse_key = four_meta_item_str(dst, pkt.dport, src, pkt.sport)
        if reverse_key in self.stream_dic:
            self.stream_dic[reverse_key].flush_seq(pkt.ack)
        if key not in self.stream_dic:
            self.stream_dic[key] = self._build_stream_base(pkt, src, dst)
            self.stream_dic[key].set_file_name(str(self.meta_item))
        return self.stream_dic[key].append_pkt(pkt, src, dst)

    def _build_stream_base(self, pkt: TCP, src: Buffer, dst: Buffer) -> OneStreamBase:
        return OneStreamBase(
            src, dst, pkt.sport, pkt.dport, writer=self.writer, timestamp=self.timestamp)

    def flush(self):
        for key, stream in self.stream_dic.items():
            stream.flush()


class ReConstructTwoToOne(ReContructBase):

    def __init__(self, *args, **kwargs):
        super(ReConstructTwoToOne, self).__init__(*args, **kwargs)

    def _hash_for_four_meta(self, src: Buffer, sport: int, dst: Buffer, dport: int):
        return TwoToOneMetaItem(src, sport, dst, dport)

    def _construct(self, src: Buffer, dst: Buffer,
                   sport: int, dport: int, timestamp: float) -> StreamInterface:
        return TwoToOneStreamBase(src, dst, sport, dport, self.target_writer, timestamp)
