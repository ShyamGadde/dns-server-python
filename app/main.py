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

    def pack(self) -> bytes:
        flags = (
            (self.qr << 15)
            | (self.opcode << 11)
            | (self.aa << 10)
            | (self.tc << 9)
            | (self.rd << 8)
            | (self.ra << 7)
            | (self.z << 4)
            | self.rcode
        )
        return struct.pack(
            ">HHHHHH",
            self.id,
            flags,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount,
        )


@dataclass
class DNSQuestion:
    name: str
    type: int
    class_: int

    def pack(self):
        parts = self.name.split(".")
        qname = b"".join(len(p).to_bytes(1, "big") + p.encode("ascii") for p in parts)
        qname += b"\x00"
        return qname + struct.pack("!HH", self.type, self.class_)


@dataclass
class DNSAnswer:
    name: str
    type: int
    class_: int
    ttl: int
    rdlength: int
    rdata: str

    def pack(self):
        parts = self.name.split(".")
        name = b"".join(len(p).to_bytes(1, "big") + p.encode("ascii") for p in parts)
        name += b"\x00"
        rdata = struct.pack("!BBBB", *[int(part) for part in self.rdata.split(".")])
        return (
            name
            + struct.pack("!HHIH", self.type, self.class_, self.ttl, self.rdlength)
            + rdata
        )


def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            data, source = udp_socket.recvfrom(1024)

            id = struct.unpack("!H", data[0:2])[0]
            qr = data[2] >> 7
            op = (data[2] >> 3) & 0b1111
            rd = data[2] & 0b1
            rcode = 0 if op == 0 else 4

            response = b""

            header_packed = DNSHeader(
                id, qr, op, 0, 0, rd, 0, 0, rcode, 1, 1, 0, 0
            ).pack()
            question_packed = DNSQuestion("codecrafters.io", 1, 1).pack()
            answer_packed = DNSAnswer("codecrafters.io", 1, 1, 60, 4, "8.8.8.8").pack()

            response += header_packed + question_packed + answer_packed
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
