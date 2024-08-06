import pyshark
import hashlib
from scapy.all import rdpcap

def get_packet_count(pcap_file):
    packets = rdpcap(pcap_file)
    return len(packets)

def hash_packet(packet_info):
    packet_str = f"{packet_info['src']}-{packet_info['dst']}-{packet_info['sport']}-{packet_info['dport']}"
    return hashlib.md5(packet_str.encode()).hexdigest()

def extract_packet_info(pcap_file):
    packets = []
    cap = pyshark.FileCapture(pcap_file, keep_packets=False)
    for row_num, packet in enumerate(cap, start=1):
        try:
            packet_info = {
                'row_num': row_num,
                'src': packet.ip.src if hasattr(packet, 'ip') else None,
                'dst': packet.ip.dst if hasattr(packet, 'ip') else None,
                'sport': packet[packet.transport_layer].srcport if hasattr(packet, 'transport_layer') else None,
                'dport': packet[packet.transport_layer].dstport if hasattr(packet, 'transport_layer') else None,
            }
            packet_info['hash'] = hash_packet(packet_info)
            packets.append(packet_info)
        except AttributeError:
            continue
    cap.close()
    return packets

def find_missing_packets(pcap1_packets, pcap2_packets):
    pcap2_hashes = {pkt['hash'] for pkt in pcap2_packets}
    missing_packets = [pkt for pkt in pcap1_packets if pkt['hash'] not in pcap2_hashes]
    return missing_packets

def compare_pcaps(pcap_file1, pcap_file2):
    print(f"Comparing {pcap_file1} with {pcap_file2}...\n")

    total_packets_1 = get_packet_count(pcap_file1)
    total_packets_2 = get_packet_count(pcap_file2)

    pcap1_packets = extract_packet_info(pcap_file1)
    pcap2_packets = extract_packet_info(pcap_file2)

    missing_packets = find_missing_packets(pcap1_packets, pcap2_packets)

    total_missing = len(missing_packets)

    print(f"Total packets in {pcap_file1}: {total_packets_1}")
    print(f"Total packets in {pcap_file2}: {total_packets_2}")
    print(f"Total missing packets: {total_missing}")

    if total_missing > 0:
        print("\nDetails of missing packets:")
        for packet in missing_packets:
            print(f"Row: {packet['row_num']}, Src: {packet['src']}, Dst: {packet['dst']}, Sport: {packet['sport']}, Dport: {packet['dport']}")

pcap_file1 = 'c:/Users/username/Desktop/example1.pcap'
pcap_file2 = 'c:/Users/username/Desktop/example2.pcap'
compare_pcaps(pcap_file1, pcap_file2)
