import argparse

import main as ping

minDelay = 100000
maxDelay = 0
packetlosts = []
def main(assigned_args: list = None):
    parser = argparse.ArgumentParser(prog="ping")
    parser.add_argument(dest="dest_addr", metavar="DEST_ADDR", nargs="*", default=("example.com", "8.8.8.8"), help="The destination address, can be an IP address or a domain name.")
    parser.add_argument("-c", "--count", dest="count", metavar="COUNT", type=int, default=4, help="Default  4.")
    parser.add_argument("-w", "--wait", dest="timeout", metavar="TIMEOUT", type=float, default=4, help="Default  4.")
    parser.add_argument("-i", "--interval", dest="interval", metavar="INTERVAL", type=float, default=0, help="Default  0.")
    parser.add_argument("-I", "--interface", dest="interface", metavar="INTERFACE", default="", help="LINUX ONLY.")
    parser.add_argument("-t", "--ttl", dest="ttl", metavar="TTL", type=int, default=64, help="Default  64.")
    parser.add_argument("-l", "--load", dest="size", metavar="SIZE", type=int, default=56, help="payload size in bytes. Default is 56.")
    args = parser.parse_args(assigned_args)
    try:
        for addr in args.dest_addr:
            delays,packetLossNumber=ping.verbose_ping(addr, count=args.count, ttl=args.ttl, timeout=args.timeout, size=args.size, interval=args.interval, interface=args.interface)
            for i in delays:
                if maxDelay < int(i):
                    maxDelay=int(i)
                if minDelay > int(i):
                    minDelay =int(i)
            packetlosts.append({addr:packetLossNumber})
        # print("minDelay= ", minDelay)
        # print("maxDelay= ", maxDelay)
        return packetlosts,minDelay,maxDelay
    except KeyboardInterrupt:
        return packetlosts, minDelay, maxDelay
        pass

