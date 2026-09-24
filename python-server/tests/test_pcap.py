import struct

from app.malware_intel.pcap import PcapDecodeError, decode_pcap


def _ethernet_ipv4_udp_packet():
    ethernet = b"\x00" * 12 + struct.pack(">H", 0x0800)
    ip = bytes([0x45, 0, 0, 32, 0, 0, 0, 0, 64, 17, 0, 0, 8, 8, 8, 8, 1, 1, 1, 1])
    udp = struct.pack(">HHHH", 5353, 53, 12, 0) + b"test"
    return ethernet + ip + udp


def test_decode_classic_pcap_extracts_protocols_endpoints_and_ports():
    packet = _ethernet_ipv4_udp_packet()
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record = struct.pack("<IIII", 1, 2, len(packet), len(packet)) + packet

    result = decode_pcap(header + record)

    assert result["packetCount"] == 1
    assert result["protocols"] == {"udp": 1}
    assert result["endpoints"]["8.8.8.8"] == 1
    assert result["ports"]["8.8.8.8:5353"] == 1


def test_decode_rejects_unknown_capture_format():
    try:
        decode_pcap(b"not-a-pcap" + b"\x00" * 14)
    except PcapDecodeError as error:
        assert "Unsupported capture format" in str(error)
    else:
        raise AssertionError("Expected invalid PCAP to be rejected")


def test_decode_extracts_dns_query_and_http_host_metadata():
    ethernet = b"\x00" * 12 + struct.pack(">H", 0x0800)
    ip = bytes([0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 8, 8, 8, 8, 1, 1, 1, 1])
    dns = struct.pack(">HHHHHH", 1, 0, 1, 0, 0, 0) + b"\x03www\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
    udp = struct.pack(">HHHH", 53000, 53, 8 + len(dns), 0) + dns
    dns_packet = ethernet + ip[:2] + struct.pack(">H", len(ip) + len(udp)) + ip[4:] + udp
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record = struct.pack("<IIII", 1, 2, len(dns_packet), len(dns_packet)) + dns_packet

    result = decode_pcap(header + record)

    assert result["dnsQueries"] == {"www.example.com": 1}