import os
import sys
from dpkt.ip import IP
from dpkt.tcp import TCP
from dpkt.dpkt import NeedData
from dpkt.pcap import Reader as PReader
from dpkt.ethernet import Ethernet
from socket import inet_ntop
from socket import AF_INET
from socket import AF_INET6
from threading import Thread
from collections import defaultdict
from .protocol.dcmReader import readDcm
from .protocol.state_astm import StateAstm
from .protocol.state_hl7 import StateHL7
from pydicom.errors import InvalidDicomError
import dpkt

from .nioWrite import NIOWriter 
import time

def readByProtocol(path, protocol):
    if os.path.isdir(path):
        for p in os.listdir(path):
            readByProtocol(os.path.join(path, p), protocol)
    else:
        if 'DICOM' in protocol or 'dicom' in protocol:
            try:
                readDcm(path)
            except InvalidDicomError:
                if 'hl7' in protocol or 'HL7' in protocol:
                    s = StateHL7(path)
                    s.state()
                if 'astm' in protocol or 'ASTM' in protocol:
                    A = StateAstm(path)
                    A.state()
        elif 'hl7' in protocol or 'HL7' in protocol:
            s = StateHL7(path)
            s.state()
            if 'astm' in protocol or 'ASTM' in protocol:
                A = StateAstm(path)
                A.state()
        elif 'astm' in protocol or 'ASTM' in protocol:
            A = StateAstm(path)
            A.state()
# 一些提前定义的变量
LengthTag = 1000

# 前一个key
head = 0
# 后一个key
after = 1
# 源地址端口
srcPort = 2
# 目的地址端口
dstPort = 3
# 时间戳 （用于超时判定，非常规超时判断）
timeTag = 4
# 文件名称，用于数据量过大时追加文件
fileTag = 5
# 内容开始位置
content = 6

# 用于超时的时间限制
# 即每隔多长时间检查一次字典中的无效数据
TimeThreshold = 1



def FINDeal(dic, value, pkt, key1, key2, writer, absPath, typer, src, dst):
    key3 = dst + ':' + str(pkt.dport) + '-'  + src + ':' + str(pkt.sport) +  '_' + str(pkt.ack)
    Another = dic.pop(key3, None)
    if not Another is None:
        if key3 == Another[head]:
            dic.pop(Another[after], None)
        else:
            dic.pop(Another[head], None)
        item = {}
        item['fileName'] = 'Y_%s' % (Another[fileTag])
        item['absPath'] = os.path.join(absPath, typer)
        item['data']=Another[content:]
        writer.put(item)
    item1 = {}
    item1['fileName'] = 'Y_%s' % (value[fileTag])
    item1['absPath'] = os.path.join(absPath, typer)  
    item1['data']=value[content:]
    writer.put(item1)

def NFINDeal(value, writer, absPath, typer):
    item1 = {}
    item1['fileName'] = 'N_%s' % (value[fileTag])
    item1['absPath'] = os.path.join(absPath, typer)  
    item1['data']=value[content:]
    writer.put(item1)

def WriteFileOnly(writer, value, absPath, typer):
    item = {}
    item['fileName'] = 'Y_%s' % (value[fileTag])
    item['absPath'] = os.path.join(absPath, typer)
    item['data'] = value[content:]
    writer.put(item)
    return value[0 : content]

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

def construct(absPath, target, typer):
    if not os.path.exists(os.path.join(absPath, typer)):
        os.mkdir(os.path.join(absPath, typer))
    # fpcap = open(os.path.join(absPath, target), 'rb')
    writer = NIOWriter()
    t = Thread(target=writer.start_loop)
    time.sleep(1)
    t.start()
    dic = defaultdict(None)
    i = 0
    f = open(os.path.join(absPath, target), 'rb')
    pcap_reader = PReader(f)
    start = time.time()
    allTime = start
    for timestamp, pkt in pcap_reader:
        eth = None
        try:
            eth = Ethernet(pkt)
        except NeedData:
            continue
        if not isinstance(eth.data, IP):
            continue
        pkt = eth.data
        if not isinstance(pkt.data, TCP):
            continue
        src = inet_to_str(pkt.src)
        dst = inet_to_str(pkt.dst)
        pkt = pkt.data

    
        i += 1
        # 对pkt进行相应的处理
        now = time.time()
        if now - start >= TimeThreshold:
            for key in list(dic.keys()):
                if not key in dic:
                    continue
                value = dic[key]
                if (now - value[timeTag]) >= TimeThreshold:
                    dic.pop(value[head], None)
                    dic.pop(value[after], None)
                # NFINDeal(value, writer, absPath, typer)
            start = time.time()
       
        seq = pkt.seq + len(pkt.data)

        if (pkt.flags & 2) == 2:
            seq += 1
        
        key1 = src + ':' + str(pkt.sport) + '-' + dst + ':' + str(pkt.dport) + '_' + str(pkt.seq)
        key2 = src + ':' + str(pkt.sport) + '-' + dst + ':' + str(pkt.dport) + '_' + str(seq)
        value = dic.pop(key1, None)
        
        if not value is None:
            # 追加
            if key1 == value[head] and value[head] != value[after]:
                # 重传数据包
                # 略过
                continue
            # 非重传数据包
            value.append(pkt.data)
            if (pkt.flags & 1) == 1:
                # 清除键值
                dic.pop(value[head], None)
                dic.pop(value[after], None)
                FINDeal(dic, value, pkt, key1, key2, writer, absPath, typer, src, dst)
                # if not dic.pop(key1, None) is None:
                #     print('here')
                continue
            # 乱序数据包
            while True:
                current = dic.pop(key2, None)
                if current is None:
                    break
                # print(i)
                if key2 == current[head]:
                    key2 = current[after]
                    value += current[content:]
                    continue
                else:
                    break
            # 设置时间戳
            if (len(value) >= LengthTag):
                value = WriteFileOnly(writer, value, absPath, typer)
                dic.pop(key1, None)
                dic.pop(key2, None)
                dic[key1] = value
                dic[key2] = value
            value[after] = key2
            value[timeTag] = time.time()
            dic[key2] = value
            continue
        else:
            # 前增
            value = dic.pop(key2, None)
            if not value is None:
                # 在前增
                if key1 == value[after]:
                    # 重传数据包
                    # 略过
                    continue
                # 非重传数据包
                value.insert(content, pkt.data)
                # 设置时间戳
                value[timeTag] = time.time()
                value[head] = key1
                dic[key1] = value
                continue
            else:
                value = [key1, key2, src + '-' + str(pkt.sport), dst + '-' + str(pkt.dport), time.time()] 
                value.append(str(value[timeTag]) + '_' + value[srcPort] + '_' + value[dstPort])
                value.append(pkt.data)
                dic[key1] = value
                dic[key2] = value
                continue
    # print(time.time() - allTime)
    while t.isAlive():
        writer.quit()
        time.sleep(1)
    # print('hl7 start')
    # if 'ftp' in typer:
    if os.path.exists(os.path.join(absPath, typer)) and len(os.listdir(os.path.join(absPath, typer))) > 0:
        for path in os.listdir(os.path.join(absPath, typer)):
            readByProtocol(os.path.join(absPath, typer, path), typer)
    # print('end hl7')

    # elif typer == 'hl7':
    #     for path in os.listdir(os.path.join(absPath, typer)):
    #         s = StateHL7(os.path.join(absPath, typer, path))
    #         s.state()

# if __name__ == '__main__':
    # construct('E:\\29161\\Destop\\medical_instance\\pcap', 'test.pcap', 'http')
    # construct('pcap', 'ftp_download.pcap', 'ftp')
    # construct('pcap/1589974224/', 'ftp.pcap', 'DICOM|ftp')
    # construct('E:\\29161\\Destop\\medical_instance\\pcap', 'http_download.pcap', 'http')
    # construct('E:\\29161\\Destop\\medical_instance\\pcap', 'http_download.pcap', 'http')
    # import threading
    # import dpktHttpConstruct
    # t1 = threading.Thread(target=dpktHttpConstruct.construct, args=['pcap/1589985453/', 'http.pcap', 'DICOM|http', True])
    # import dpktConstruct
    # t2 = threading.Thread(target=construct, args=['pcap/1589985453/', 'ftp.pcap', 'DICOM|ftp'])
    # t1.start()
    # t2.start()