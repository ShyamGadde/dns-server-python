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

    @classmethod
    def unpack(cls, data: bytes):
        id, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data)
        qr = flags >> 15
        opcode = (flags >> 11) & 0b1111
        aa = (flags >> 10) & 0b1
        tc = (flags >> 9) & 0b1
        rd = (flags >> 8) & 0b1
        ra = (flags >> 7) & 0b1
        z = (flags >> 4) & 0b111
        rcode = 0 if opcode == 0 else 4
        return cls(
            id, qr, opcode, aa, tc, rd, ra, z, rcode, qdcount, ancount, nscount, arcount
        )


@dataclass
class DNSQuestion:
    name: str
    type_: int
    class_: int

    def pack(self):
        name = (
            b"".join(
                len(p).to_bytes(1, "big") + p.encode("ascii")
                for p in self.name.split(".")
            )
            + b"\x00"
        )
        return name + struct.pack("!HH", self.type_, self.class_)

    @classmethod
    def unpack(cls, data: bytes):
        parts = []
        while True:
            length = data[0]
            if length == 0:
                break
            parts.append(data[1 : length + 1].decode("ascii"))
            data = data[length + 1 :]
        name = ".".join(parts)

        type_, class_ = struct.unpack("!HH", data[:4])
        data = data[4:]

        return cls(name, type_, class_), data


@dataclass
class DNSAnswer:
    name: str
    type_: int
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
            + struct.pack("!HHIH", self.type_, self.class_, self.ttl, self.rdlength)
            + rdata
        )


@dataclass
class DNSQuery:
    header: DNSHeader
    question: DNSQuestion

    @classmethod
    def parse(cls, data):
        header = DNSHeader.unpack(data[:12])
        question, _ = DNSQuestion.unpack(data[12:])
        return cls(header, question)


def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            data, source = udp_socket.recvfrom(1024)

            query = DNSQuery.parse(data)
            print("query", query)
            print("query.header", query.header)
            print("query.question", query.question)

            response = b""

            response_header = DNSHeader(
                id,
                1,
                query.header.opcode,
                0,
                0,
                query.header.rd,
                0,
                0,
                query.header.rcode,
                1,
                1,
                0,
                0,
            ).pack()

            response_question = DNSQuestion(query.question.name, 1, 1).pack()
            response_answer = DNSAnswer(
                query.question.name, 1, 1, 60, 4, "8.8.8.8"
            ).pack()

            response += response_header + response_question + response_answer
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
