import socket
import struct
from dataclasses import dataclass


@dataclass
class DNSHeader:
    id: int
    qr: int
    opcode: int
    aa: int
    tc: int
    rd: int
    ra: int
    z: int
    rcode: int
    qdcount: int
    ancount: int
    nscount: int
    arcount: int


@dataclass
class DNSQuestion:
    qname: str
    qtype: int
    qclass: int


def pack_dns_header(header: DNSHeader) -> bytes:
    flags = (
        (header.qr << 15)
        | (header.opcode << 11)
        | (header.aa << 10)
        | (header.tc << 9)
        | (header.rd << 8)
        | (header.ra << 7)
        | (header.z << 4)
        | header.rcode
    )
    return struct.pack(
        ">HHHHHH",
        header.id,
        flags,
        header.qdcount,
        header.ancount,
        header.nscount,
        header.arcount,
    )


def pack_dns_question(question: DNSQuestion) -> bytes:
    # Encode qname
    parts = question.qname.split(".")
    qname = b"".join(len(p).to_bytes(1, "big") + p.encode("ascii") for p in parts)
    qname += b"\x00"  # append null byte at the end

    # Encode qtype and qclass as 2-byte integers (big endian)
    qtype = question.qtype.to_bytes(2, byteorder="big")
    qclass = question.qclass.to_bytes(2, byteorder="big")

    return qname + qtype + qclass


def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            response = b""

            header = DNSHeader(1234, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0)
            question = DNSQuestion("codecrafter.io", 1, 1)

            response += pack_dns_header(header) + pack_dns_question(question)
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
