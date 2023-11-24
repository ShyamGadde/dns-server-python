import socket
import struct
from dataclasses import dataclass


@dataclass
class DNSHeader:
    id_: int
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
            self.id_,
            flags,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount,
        )

    @classmethod
    def unpack(cls, data: bytes):
        id_, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data)
        qr = flags >> 15
        opcode = (flags >> 11) & 0b1111
        aa = (flags >> 10) & 0b1
        tc = (flags >> 9) & 0b1
        rd = (flags >> 8) & 0b1
        ra = (flags >> 7) & 0b1
        z = (flags >> 4) & 0b111
        rcode = flags & 0b1111
        return cls(
            id_,
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            z,
            rcode,
            qdcount,
            ancount,
            nscount,
            arcount,
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
    def unpack(cls, data: bytes, message: bytes):
        parts = []
        jumped = False
        jump_offset = 0

        while True:
            length = data[0]
            if length == 0:
                break

            # Check if this is a pointer
            if length >= 0xC0:
                if not jumped:
                    jump_offset = len(data) - 1
                    jumped = True

                # Calculate the offset and jump to it
                offset = ((length & 0x3F) << 8) | data[1]
                data = message[offset:]
                continue

            parts.append(data[1 : length + 1].decode("ascii"))
            data = data[length + 1 :]

            if jumped:
                data = data[jump_offset:]
                break

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
    questions: list[DNSQuestion]

    @classmethod
    def parse(cls, payload):
        header = DNSHeader.unpack(payload[:12])

        questions: list[DNSQuestion] = []
        unprocessed = payload[12:]
        for _ in range(header.qdcount):
            question, unprocessed = DNSQuestion.unpack(unprocessed, message=payload)
            questions.append(question)

        return cls(header, questions)


class DNSResponse:
    @staticmethod
    def build_from(query: DNSQuery):
        response = b""

        response += DNSHeader(
            id_=query.header.id_,
            qr=1,
            opcode=query.header.opcode,
            aa=0,
            tc=0,
            rd=query.header.rd,
            ra=0,
            z=0,
            rcode=(0 if query.header.opcode == 0 else 4),
            qdcount=query.header.qdcount,
            ancount=query.header.qdcount,
            nscount=0,
            arcount=0,
        ).pack()

        for question in query.questions:
            print(question)
            response += question.pack()

        for question in query.questions:
            response += DNSAnswer(
                name=question.name,
                type_=1,
                class_=1,
                ttl=60,
                rdlength=4,
                rdata="8.8.8.8",
            ).pack()

        return response


def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            data, source = udp_socket.recvfrom(1024)

            query = DNSQuery.parse(data)

            response = DNSResponse.build_from(query)
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
