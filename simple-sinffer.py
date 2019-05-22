import socket
import os
import contextlib

@contextlib.contextmanager
def make_sniffer(host=None, port=None):
    if host is None:
        host = socket.gethostbyname(socket.gethostname())
    if port is None:
        port = 0

    if os.name == 'nt':
        protocol = socket.IPPROTO_IP
    else:
        protocol = socket.IPPROTO_ICMP

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, protocol)
    sniffer.bind((host, port))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    try:
        yield sniffer
    finally:
        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)


def test():
    with make_sniffer() as sniffer:
        ips = set()
        while True:
            data, address = sniffer.recvfrom(65536)
            data = None
            if address not in ips:
                print(address)
                ips.add(address)
            #print(address, data, sep='\n')

def ip_counter():
    with make_sniffer() as sniffer:
        import collections
        import time
        import threading

        c = collections.Counter()
        def task(c, interval):
            # add bit counter
            while True:
                time.sleep(interval)
                os.system("clear")
                for ip, count  in sorted(c.items(), key=lambda x: x[1], reverse=True):
                    print(ip, count)
        threading.Thread(target=task, args=(c, 1)).start()

        while True:
            _, address = sniffer.recvfrom(65536)
            ip = address[0]
            c.update({ip: 1})


if __name__ == '__main__':
    ip_counter()

