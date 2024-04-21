import queue
import dpkt
from typing import Tuple
from collections import defaultdict
from dpkt.ip import IP
from dpkt.tcp import TCP, TH_FIN, TH_SYN, TH_RST, TH_PUSH, TH_ACK, TH_URG, TH_ECE, TH_CWR, TH_NS
from dpkt.dpkt import NeedData
from dpkt.pcap import Reader as PReader
from dpkt.ethernet import Ethernet
from threading import Thread
from socket import inet_ntop
from socket import AF_INET
from socket import AF_INET6
import time
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


class SubStreamBase:

    def __init__(self, head_seq: int, next_seq: int, writer: NIOWriter, abs_path: str, timestamp: time.time()) -> None:
        self.head_seq = head_seq
        self.next_seq = next_seq
        self.datas = []
        self.writer = writer
        self.timestamp = timestamp
        self.abs_path = abs_path

    def is_head_for_seq(self, seq: int) -> bool:
        return self.head_seq == seq

    def is_next_for_seq(self, seq: int) -> bool:
        return self.next_seq == seq

    def is_euqals_for_head_and_next(self) -> bool:
        return self.head_seq == self.next_seq

    def append_pkt(self, pkt: TCP, next_seq: int):
        self.datas.append(pkt.data)
        self.next_seq = next_seq

    def insert_pkt(self, pkt: TCP):
        self.datas.insert(0, pkt.data)
        self.head_seq = pkt.seq

    def append(self, stream: object):
        self.datas.extend(stream.datas)
        self.head_seq = min(self.head_seq, stream.head_seq)
        self.next_seq = max(self.next_seq, stream.next_seq)

    def flush(self):
        if self.writer is None:
            return
        self.writer.put(self.abs_path, self.datas)
        self.datas = []


class StreamBase:
    def __init__(self, src: Buffer, dst: Buffer,
                 sport: int, dport: int, writer: NIOWriter = None, timestamp=time.time()):
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

    def _file_name(self, seq_for_stream=0):
        return f'{self.timestamp}-{inet_to_str(self.src)}-{self.sport}_{inet_to_str(self.dst)}-{self.dport}_{seq_for_stream}'

    def append_pkt(self, pkt: TCP) -> bool:
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
            self.stream_count -= 1
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
            self._build_new_stream(seq, next_seq, pkt)
            return
        if self.dic[next_seq].is_next_for_seq(next_seq):
            return
        pkts = self.dic.pop(next_seq)
        self.min_seq_dic.pop(next_seq)
        pkts.insert_pkt(pkt)
        self.dic[seq] = pkts
        self.min_seq_dic[seq] = pkts

    def _build_new_stream(self, seq: int, next_seq: int, pkt: TCP):
        self.stream_count += 1
        new_stream = SubStreamBase(seq, next_seq, self.target_writer, self._file_name(
            self.stream_count), self.timestamp)
        self.dic[seq] = new_stream
        self.dic[next_seq] = new_stream
        new_stream.append_pkt(pkt, next_seq)
        self.min_seq_dic[seq] = new_stream

    def __hash__(self) -> int:
        return hash(self.src) ^ hash(self.dst) ^ hash(self.sport) ^ hash(self.dport)

    def __eq__(self, value: object) -> bool:
        return self.src == value.src and self.dst == value.dst and self.sport == value.sport and self.dport == value.dport


class ReContructBase:

    def __init__(self, target_path=None):
        self.seq_pqueue = queue.PriorityQueue()
        self.stream_dic = defaultdict(None)
        self.target_writer = NIOWriter(dir=target_path)
        self.write_thread = Thread(target=self.target_writer.start_loop)
        self.write_thread.start()

    def set_file(self, abs_path: str = '', file_path: str = ''):
        self.pcap_file = os.path.join(abs_path, file_path)

    def construct(self):
        with open(self.pcap_file, 'rb') as f:
            pcap_reader = PReader(f)
            for timestamp, pkt in pcap_reader:
                eth = self.__parse_eth(pkt)
                if eth is None:
                    continue
                tcp, src, dst = self.__upack_tcp(eth)
                if tcp is None:
                    continue
                self.__construct(tcp, src, dst)

        for stream_value in self.stream_dic.values():
            stream_value.flush()

        while self.write_thread.is_alive():
            self.target_writer.quit()
            time.sleep(1)

    def __parse_eth(self, pkt: dpkt.Packet) -> Ethernet:
        try:
            return Ethernet(pkt)
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
        return f"{inet_to_str(src)}:{sport}_{inet_to_str(dst)}:{dport}"

    def __construct(self, pkt: TCP, src: Buffer, dst: Buffer):
        sport = pkt.sport
        dport = pkt.dport
        key = self._hash_for_four_meta(src, sport, dst, dport)
        if key not in self.stream_dic:
            self.stream_dic[key] = StreamBase(
                src, dst, sport, dport, writer=self.target_writer)

        if self.stream_dic[key].append_pkt(pkt):
            self.stream_dic.pop(key)
