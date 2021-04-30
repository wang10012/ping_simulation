from struct import *
import time
import socket
import select
import argparse

from pycallgraph import PyCallGraph
from pycallgraph.output import GraphvizOutput


class icmp_echo:
    def __init__(self):
        self.type = 8
        self.code = 0
        self.id = 2
        self.sequence = 0
        self.databody = b'dkasdkaddakdakdakdqkdhkakdadaswq'  # 32位数据

    def check_sum(self):
        """
        计算校验和
        :return:
        """
        icmp_package = pack('>bbHHH32s', self.type, self.code, 0, self.id, self.sequence, self.databody)  # checksum先设为0
        n = len(icmp_package)
        m = n % 2
        sum = 0
        for i in range(0, n - m, 2):
            sum += (icmp_package[i]) + ((icmp_package[i + 1]) << 8)
        if m:
            sum += (icmp_package[-1])
        sum = (sum >> 16) + (sum & 0xffff)
        sum += (sum >> 16)
        result = ~sum & 0xffff
        result = result >> 8 | (result << 8 & 0xff00)
        self.icmp_checksum = result
        return result

    def icmp_package(self):
        """
        构建icmp报文
        :return:
        """
        self.check_sum()
        icmp_package = pack('>bbHHH32s', self.type, self.code, self.icmp_checksum, self.id, self.sequence,
                            self.databody)
        return icmp_package


def send_ping(icmp_package, address):
    wsj_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
    wsj_socket.settimeout(1)
    send_time = time.time()
    wsj_socket.sendto(icmp_package, (address, 80))
    return send_time, wsj_socket


def reply_ping(wsj_socket, send_time, icmp_sequence, timeout=1):
    while True:
        TTL = 128
        started_time = time.time()
        wsj_select = select.select([wsj_socket], [], [], timeout)
        waiting_time = (time.time() - started_time)
        # 没有返回可读的内容，判断超时
        if wsj_select[0] == []:
            return -1, TTL
        time_received = time.time()
        received_package, address = wsj_socket.recvfrom(1024)
        icmp_header = received_package[20:28]
        TTL = ord(unpack("!c", received_package[8:9])[0])
        # print("TTL:" + str(TTL))
        type, code, checksum, id, sequence = unpack(">bbHHH", icmp_header)
        if type == 0 and code == 0 and sequence == icmp_sequence:
            return time_received - send_time, TTL
        timeout = timeout - waiting_time
        if timeout <= 0:
            return -1, TTL


def ping(host, flag=0, n=4, timeout=1):
    send, accept, lost = 0, 0, 0
    sum_time, shortest_time, longest_time, average_time = 0, 1000, 0, 0
    i = 1
    icmp = icmp_echo()
    try:
        address = socket.gethostbyname(host)
    except Exception:
        print("您输入的地址或域名解析有错误！")
        return
    print("\n正在Ping {0} [{1}] 具有32字节的数据：".format(host, address))
    while True:
        send = i
        icmp.sequence = i
        send_time, wsj_socket = send_ping(icmp.icmp_package(), address)
        reply_time, TTL = reply_ping(wsj_socket, send_time, i, timeout)
        try:
            if reply_time > 0:
                print("来自{0}的回复：字节=32 时间={1}ms TTL={2}".format(address, int(reply_time * 1000), TTL))

                accept += 1
                return_time = int(reply_time * 1000)
                sum_time += return_time
                if return_time > longest_time:
                    longest_time = return_time
                if return_time < shortest_time:
                    shortest_time = return_time

                time.sleep(1)
            else:
                time.sleep(1)
                lost += 1
                print("请求超时。")
        except KeyboardInterrupt:
            print("终止！")
            print("\n{0}的Ping统计信息:".format(address))
            print("\t数据包：已发送={0},接收={1}，丢失={2}（{3}%丢失），\n往返行程的估计时间（以毫秒为单位）：\n\t最短={4}ms，最长={5}ms，平均={6}ms".format(
                i, accept, i - accept, (i - accept) / i * 100, shortest_time, longest_time, int(sum_time / send)))

            return

        if send == n and flag == 0:
            print("\n{0}的Ping统计信息:".format(address))
            print("\t数据包：已发送={0},接收={1}，丢失={2}（{3}%丢失），\n往返行程的估计时间（以毫秒为单位）：\n\t最短={4}ms，最长={5}ms，平均={6}ms".format(
                i, accept, i - accept, (i - accept) / i * 100, shortest_time, longest_time, int(sum_time / send)))
            break
        i += 1



if __name__ == '__main__':
    # with PyCallGraph(output=GraphvizOutput()):
    #
    #     print("请输入您需要Ping的主机或域名")
    #     host = input()
    #     ping(host)

    parser = argparse.ArgumentParser(description='implementation of Ping by WSJ')
    parser.add_argument('input', help='输入想要ping的目标URL')
    parser.add_argument('-t', help='无限循环ping指令，可以用Ctrl c退出循环', action='count', default=0)
    parser.add_argument('-n', help='输入参数控制ping请求的次数，默认为4', default=4)
    parser.add_argument('-w', help='设置timeout值（单位：ms）', default=1000)
    args = parser.parse_args()
    ping(args.input, flag=int(args.t), n=int(args.n), timeout=int(args.w) / 1000)
