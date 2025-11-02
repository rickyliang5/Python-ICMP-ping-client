#!/usr/bin/env python3
"""
simple_ping.py
A minimal ICMP echo (ping) client.

Usage:
    sudo python3 simple_ping.py <host> [count] [timeout_seconds]

Example:
    sudo python3 simple_ping.py 8.8.8.8 5 1
"""
import socket
import os
import sys
import struct
import time
import select
import statistics

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0

def checksum(data: bytes) -> int:
    # Standard Internet checksum (RFC 1071)
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        w = data[i] << 8 | data[i+1]
        s = (s + w) & 0xffffffff
    # add carries
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def create_packet(identifier: int, sequence_number: int, payload: bytes) -> bytes:
    header = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, 0, 0, identifier, sequence_number)
    chksum = checksum(header + payload)
    header = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, 0, chksum, identifier, sequence_number)
    return header + payload

def parse_icmp_packet(packet: bytes):
    # IP header length from first byte
    ip_header = packet[:20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    ihl = (iph[0] & 0x0F) * 4
    icmp_offset = ihl
    icmp_header = packet[icmp_offset:icmp_offset+8]
    (type_, code, chksum, p_id, seq) = struct.unpack('!BBHHH', icmp_header)
    payload = packet[icmp_offset+8:]
    return type_, code, p_id, seq, payload

def ping(host: str, count: int = 4, timeout: float = 1.0):
    try:
        dest = socket.gethostbyname(host)
    except socket.gaierror as e:
        print(f"Cannot resolve '{host}': {e}")
        return

    print(f"PING {host} ({dest}): {64} bytes of data")

    # Raw socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.setblocking(False)

    identifier = os.getpid() & 0xFFFF
    seq = 0
    rtts = []
    sent = 0
    received = 0

    for i in range(count):
        seq += 1
        # payload: timestamp + filler
        send_time = time.time()
        payload = struct.pack('d', send_time) + (b'Q' * 48)
        pkt = create_packet(identifier, seq, payload)
        try:
            sock.sendto(pkt, (dest, 1))
            sent += 1
        except PermissionError:
            print("Permission denied: you probably need to run this as root/administrator.")
            sock.close()
            return
        except Exception as e:
            print("Send error:", e)
            sock.close()
            return

        # wait for reply
        start_wait = time.time()
        while True:
            ready = select.select([sock], [], [], timeout)
            if ready[0]:
                recv_packet, addr = sock.recvfrom(1024)
                try:
                    type_, code, p_id, p_seq, payload = parse_icmp_packet(recv_packet)
                except Exception:
                    continue
                # match identifier and sequence
                if type_ == ICMP_ECHO_REPLY and p_id == identifier and p_seq == seq:
                    # extract timestamp from payload if present
                    try:
                        sent_ts = struct.unpack('d', payload[:8])[0]
                        rtt = (time.time() - sent_ts) * 1000.0  # ms
                    except Exception:
                        rtt = (time.time() - send_time) * 1000.0
                    rtts.append(rtt)
                    received += 1
                    print(f"{len(payload)+8} bytes from {addr[0]}: icmp_seq={seq} ttl=? time={rtt:.3f} ms")
                    break
                else:
                    # not our packet; ignore and continue waiting until timeout
                    continue
            else:
                # timeout for this attempt
                print(f"Request timed out for icmp_seq={seq}")
                break

            if time.time() - start_wait >= timeout:
                print(f"Request timed out for icmp_seq={seq}")
                break

        # small delay between pings
        time.sleep(0.2)

    sock.close()
    # summary
    loss = 0 if sent == 0 else ((sent - received) / sent) * 100.0
    print(f"\n--- {host} ping statistics ---")
    print(f"{sent} packets transmitted, {received} received, {loss:.1f}% packet loss")
    if rtts:
        print(f"rtt min/avg/max/stddev = {min(rtts):.3f}/{statistics.mean(rtts):.3f}/{max(rtts):.3f}/{statistics.pstdev(rtts):.3f} ms")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sudo python3 simple_ping.py <host> [count] [timeout_seconds]")
        sys.exit(1)
    host = sys.argv[1]
    count = int(sys.argv[2]) if len(sys.argv) >= 3 else 4
    timeout = float(sys.argv[3]) if len(sys.argv) >= 4 else 1.0
    ping(host, count, timeout)
