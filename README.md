# PyPing 

A Python ping implementation with CLI options. Useful for testing connectivity and latency.

## Features

- Ping multiple hosts 
- Adjust packet count, timeout, TTL
- Output round trip stats
- Handles unreachable hosts 
- Multi-threaded for speed
- Linux interface binding 

## Usage

```
usage: main.py [-h] [-c COUNT] [-w TIMEOUT] [-i INTERVAL] [-I INTERFACE] [-t TTL] [-l SIZE] [DEST_ADDR [DEST_ADDR ...]]

Ping host(s) 

positional arguments:
  DEST_ADDR             Destination IP/hostname

optional arguments:
  -h, --help            show this help message and exit
  -c COUNT, --count COUNT  
                        Number of packets
  -w TIMEOUT, --wait TIMEOUT
                        Timeout in seconds
  -i INTERVAL, --interval INTERVAL
                        Interval between packets  
  -I INTERFACE, --interface INTERFACE
                        Bind to interface
  -t TTL, --ttl TTL     Time to live
  -l SIZE, --load SIZE  Packet payload size
```

Ping example.com 4 times with 1s timeout:

```
python main.py -c 4 -w 1 example.com 
```

Ping multiple hosts:

```
python main.py google.com yahoo.com
```

## Implementation 

PyPing opens a raw ICMP socket to send and receive packets. It handles converting hostnames to IPs and binding to a source address/interface.

Each ping launches in a separate thread. Output displays per host packet loss and round trip time range. 

Packet structure follows ICMP/IP standards with checksums calculated. 

## Improvements

- [ ] Continuous ping option
- [ ] Stats output formatting  
- [ ] IPv6 support
- [ ] Windows support 

Let me know if you would like any part explained in more detail!
