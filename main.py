import argparse
import os
import socket
import struct
import select
import time
import zlib
import threading
import sys

import errors
from enums import ICMP_DEFAULT_CODE, IcmpType, IcmpTimeExceededCode, IcmpDestinationUnreachableCode


EXCEPTIONS = False
IP_HEADER_FORMAT = "!BBHHHBBHII"
ICMP_HEADER_FORMAT = "!BBHHH"
ICMP_TIME_FORMAT = "!d"
SOCKET_SO_BINDTODEVICE = 25


class pong:
    def __init__(self,dest):
        self.dest = dest
        self.packetlosts = 0
        self.sentpackets = 0
        self.delays = []

    def verbose_ping(self,dest_addr: str, count: int = 4,ttl:int =64,timeout:int =4,size :int = 56, interval: float = 0,interface:str =""):
        packetLossNumber = 0
        delays = []
        timeout = timeout
        unit = 'ms'
        for i in range(count):
            output_text = "ping '{}'".format(dest_addr)
            # output_text += " from '{}'".format(src) if src else ""
            output_text += " ... "
            delay = self.ping( dest_addr= dest_addr,timeout=timeout, seq=i,unit= unit,src_addr=None,size=size,interface=interface)
            self.sentpackets=self.sentpackets+1
            # print(output_text, end="")
            if delay is None:
                print(output_text + "Timeout > {}s".format(timeout) if timeout else "Timeout")
                self.packetlosts = self.packetlosts + 1
            else:
                print(output_text + "Reply In {value}{unit}".format(value=int(delay), unit=unit))
                self.delays.append(delay)
            if interval > 0 and i < (count - 1):
                time.sleep(interval)
        for i in delays:
            if self.maxDelay < int(i):
                self.maxDelay = int(i)
            if self.minDelay > int(i):
                self.minDelay = int(i)


    def _raise(self,err):
        if EXCEPTIONS:
            raise err

    def ones_comp_sum16(self,num1: int, num2: int) -> int:
        carry = 1 << 16
        result = num1 + num2
        return result if result < carry else result + 1 - carry


    def checksum(self,source: bytes) -> int:
        if len(source) % 2:
            source += b'\x00'
        sum = 0
        for i in range(0, len(source), 2):
            sum = self.ones_comp_sum16(sum, (source[i + 1] << 8) + source[i])
        return ~sum & 0xffff


    def read_icmp_header(self,raw: bytes) -> dict:
        icmp_header_keys = ('type', 'code', 'checksum', 'id', 'seq')
        return dict(zip(icmp_header_keys, struct.unpack(ICMP_HEADER_FORMAT, raw)))


    def read_ip_header(self,raw: bytes) -> dict:
        def stringify_ip(ip: int) -> str:
            return ".".join(str(ip >> offset & 0xff) for offset in (24, 16, 8, 0))

        ip_header_keys = ('version', 'tos', 'len', 'id', 'flags', 'ttl', 'protocol', 'checksum', 'src_addr', 'dest_addr')
        ip_header = dict(zip(ip_header_keys, struct.unpack(IP_HEADER_FORMAT, raw)))
        ip_header['src_addr'] = stringify_ip(ip_header['src_addr'])
        ip_header['dest_addr'] = stringify_ip(ip_header['dest_addr'])
        return ip_header


    def send_one_ping(self,sock: socket, dest_addr: str, icmp_id: int, seq: int, size: int):
        try:
            dest_addr = socket.gethostbyname(dest_addr)
        except socket.gaierror as err:
            raise errors.HostUnknown(dest_addr) from err
        pseudo_checksum = 0
        icmp_header = struct.pack(ICMP_HEADER_FORMAT, IcmpType.ECHO_REQUEST, ICMP_DEFAULT_CODE, pseudo_checksum, icmp_id, seq)
        padding = (size - struct.calcsize(ICMP_TIME_FORMAT)) * "Q"
        icmp_payload = struct.pack(ICMP_TIME_FORMAT, time.time()) + padding.encode()
        real_checksum = self.checksum(icmp_header + icmp_payload)
        icmp_header = struct.pack(ICMP_HEADER_FORMAT, IcmpType.ECHO_REQUEST, ICMP_DEFAULT_CODE, socket.htons(real_checksum), icmp_id, seq)
        packet = icmp_header + icmp_payload
        sock.sendto(packet, (dest_addr, 0))


    def receive_one_ping(self,sock: socket, icmp_id: int, seq: int, timeout: int) -> float:

        ip_header_slice = slice(0, struct.calcsize(IP_HEADER_FORMAT))  # [0:20]
        icmp_header_slice = slice(ip_header_slice.stop, ip_header_slice.stop + struct.calcsize(ICMP_HEADER_FORMAT))  # [20:28]
        timeout_time = time.time() + timeout
        while True:
            timeout_left = timeout_time - time.time()
            timeout_left = timeout_left if timeout_left > 0 else 0
            selected = select.select([sock, ], [], [], timeout_left)
            if selected[0] == []:  # Timeout
                raise errors.Timeout(timeout)
            time_recv = time.time()
            recv_data, addr = sock.recvfrom(1024)
            ip_header_raw, icmp_header_raw, icmp_payload_raw = recv_data[ip_header_slice], recv_data[icmp_header_slice], recv_data[icmp_header_slice.stop:]
            ip_header =self.read_ip_header(ip_header_raw)
            icmp_header = self.read_icmp_header(icmp_header_raw)
            if icmp_header['id'] and icmp_header['id'] != icmp_id:
                continue
            if icmp_header['type'] == IcmpType.TIME_EXCEEDED:
                if icmp_header['code'] == IcmpTimeExceededCode.TTL_EXPIRED:
                    raise errors.TimeToLiveExpired()
                raise errors.TimeExceeded()
            if icmp_header['type'] == IcmpType.DESTINATION_UNREACHABLE:
                if icmp_header['code'] == IcmpDestinationUnreachableCode.DESTINATION_HOST_UNREACHABLE:
                    raise errors.DestinationHostUnreachable()
                raise errors.DestinationUnreachable()
            if icmp_header['id'] and icmp_header['seq'] == seq:
                if icmp_header['type'] == IcmpType.ECHO_REQUEST:
                    continue
                if icmp_header['type'] == IcmpType.ECHO_REPLY:
                    time_sent = struct.unpack(ICMP_TIME_FORMAT, icmp_payload_raw[0:struct.calcsize(ICMP_TIME_FORMAT)])[0]
                    return time_recv - time_sent


    def ping(self,dest_addr: str, timeout: int = 4, unit: str = "s", src_addr: str = None, ttl: int = None, seq: int = 0, size: int = 56, interface: str = None) -> float:
        socket_type = socket.SOCK_RAW
        with socket.socket(socket.AF_INET, socket_type, socket.IPPROTO_ICMP) as sock:
            if ttl:
                if sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL):
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                if sock.getsockopt(socket.SOL_IP, socket.IP_TTL):
                    sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            if interface:
                sock.setsockopt(socket.SOL_SOCKET, SOCKET_SO_BINDTODEVICE, interface.encode())
            if src_addr:
                sock.bind((src_addr, 0))
            thread_id = threading.get_native_id() if hasattr(threading, 'get_native_id') else threading.currentThread().ident
            process_id = os.getpid()
            icmp_id = zlib.crc32("{}{}".format(process_id, thread_id).encode()) & 0xffff
            try:
                self.send_one_ping(sock=sock, dest_addr=dest_addr, icmp_id=icmp_id, seq=seq, size=size)
                delay = self.receive_one_ping(sock=sock, icmp_id=icmp_id, seq=seq, timeout=timeout)  # in seconds
            except errors.HostUnknown as err:  # Unsolved
                self._raise(err)
                return False
            except errors.PingError as err:
                self._raise(err)
                return None
            if delay is None:
                return None
            if unit == "ms":
                delay *= 1000  # in milliseconds
        return delay

def check_thread_running(threads):
    return True in [t.is_alive() for t in threads]



if __name__ == "__main__":
    pongs=[]
    threads = []
    try:
        parser = argparse.ArgumentParser(prog="ping")
        parser.add_argument(dest="dest_addr", metavar="DEST_ADDR", nargs="*", default=("example.com", "8.8.8.8"),
                            help="The destination address, can be an IP address or a domain name.")
        parser.add_argument("-c", "--count", dest="count", metavar="COUNT", type=int, default=4, help="Default  4.")
        parser.add_argument("-w", "--wait", dest="timeout", metavar="TIMEOUT", type=float, default=4,
                            help="Default  4.")
        parser.add_argument("-i", "--interval", dest="interval", metavar="INTERVAL", type=float, default=0,
                            help="Default  0.")
        parser.add_argument("-I", "--interface", dest="interface", metavar="INTERFACE", default="", help="LINUX ONLY.")
        parser.add_argument("-t", "--ttl", dest="ttl", metavar="TTL", type=int, default=64, help="Default  64.")
        parser.add_argument("-l", "--load", dest="size", metavar="SIZE", type=int, default=56,
                            help="payload size in bytes. Default is 56.")
        args = parser.parse_args(sys.argv[1:])

        for addr in args.dest_addr:
            x=pong(addr)
            pongs.append(x)
            t = threading.Thread(target=x.verbose_ping, args=(
            addr, args.count, args.ttl, args.timeout, args.size, args.interval, args.interface), daemon=True)
            threads.append(t)
        for thread in threads:
            thread.start()
        while check_thread_running(threads):
            time.sleep(0)
    except KeyboardInterrupt:
        pass
    finally:
        maxDelay=max( max(pong.delays) for pong in pongs)
        minDelay=min( min(pong.delays) for pong in pongs)
        print("maxRTT = "+str(maxDelay))
        print(" minRTT = "+str(minDelay))
        for host in pongs:
            print( "Host "+host.dest+" Had "+str(host.packetlosts)+" Packet Loss Of "+str(host.sentpackets) )

