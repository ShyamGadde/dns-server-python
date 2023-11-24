import struct
from dataclasses import dataclass

data = b"\xcdz\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0ccodecrafters\x02io\x00\x00\x01\x00\x01"


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
                data = data[1:]
                break
            parts.append(data[1 : length + 1].decode("ascii"))
            data = data[length + 1 :]
        name = ".".join(parts)

        type_, class_ = struct.unpack("!HH", data[:4])
        data = data[4:]

        return cls(name, type_, class_), data


if __name__ == "__main__":
    q, _ = DNSQuestion.unpack(data[12:])
    print(q)
    print(q.pack())
    print(q.pack() == data[12:])
