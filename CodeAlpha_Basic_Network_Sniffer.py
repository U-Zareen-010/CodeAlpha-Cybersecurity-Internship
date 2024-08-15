import socket
import struct
import textwrap

def parse_ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return format_mac_addr(dest_mac), format_mac_addr(src_mac), socket.htons(proto), data[14:]

def format_mac_addr(bytes_addr):
    return ':'.join(f'{byte:02x}' for byte in bytes_addr).upper()

def parse_ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, dest = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, format_ipv4_addr(src), format_ipv4_addr(dest), data[header_length:]

def format_ipv4_addr(addr):
    return '.'.join(map(str, addr))

def parse_icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def parse_tcp_segment(data):
    src_port, dest_port, sequence, ack, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    return src_port, dest_port, sequence, ack, offset, data[offset:]

def parse_udp_segment(data):
    src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, length, data[8:]

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(f'\\x{byte:02x}' for byte in string)
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def start_sniffing():
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except AttributeError:
        raise RuntimeError("This code only runs on Linux-based systems where AF_PACKET is available.")

    while True:
        raw_data, _ = conn.recvfrom(65536)  # 65536 is the maximum size of an Ethernet frame.
        
        dest_mac, src_mac, eth_proto, data = parse_ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(f'Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}')

        if eth_proto == 8:  # IPv4
            version, header_length, ttl, proto, src_ip, dest_ip, data = parse_ipv4_packet(data)
            print('IPv4 Packet:')
            print(f'\tVersion: {version}, Header Length: {header_length}, TTL: {ttl}')
            print(f'\tProtocol: {proto}, Source: {src_ip}, Destination: {dest_ip}')

            if proto == 1: 
                icmp_type, code, checksum, data = parse_icmp_packet(data)
                print('ICMP Packet:')
                print(f'\tType: {icmp_type}, Code: {code}, Checksum: {checksum}')
                print(format_multi_line('\t\t', data))

            elif proto == 6: 
                src_port, dest_port, sequence, ack, offset, data = parse_tcp_segment(data)
                print('TCP Segment:')
                print(f'\tSource Port: {src_port}, Destination Port: {dest_port}')
                print(f'\tSequence: {sequence}, Acknowledgment: {ack}')
                print(format_multi_line('\t\t', data))

            elif proto == 17: 
                src_port, dest_port, length, data = parse_udp_segment(data)
                print('UDP Segment:')
                print(f'\tSource Port: {src_port}, Destination Port: {dest_port}, Length: {length}')
                print(format_multi_line('\t\t', data))

        else:
            print('Data:')
            print(format_multi_line('\t', data))

if __name__ == "__main__":
    start_sniffing()
