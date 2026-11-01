"""Bounded ordinary level-zero BOC codec, written for the custody profile.

Rejects exotic/cache/higher-level/stored-hash cells, absent cells, multiple roots,
non-forward references, unreachable cells, noncanonical padding and trailing data.
A valid BOC is NOT an authenticated transaction or a proof of chain state.
"""
from dataclasses import dataclass
from hashlib import sha256
from .errors import CustodyError

MAGIC = bytes.fromhex("b5ee9c72")
MAX_BYTES = 131072
MAX_CELLS = 256
MAX_DEPTH = 32

def crc32c(data):
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return (crc ^ 0xFFFFFFFF).to_bytes(4, "little")

@dataclass(frozen=True, eq=False)
class Cell:
    data: bytes
    bit_length: int
    refs: tuple = ()

    def __post_init__(self):
        if type(self.data) is not bytes or type(self.bit_length) is not int:
            raise CustodyError("invalid cell type")
        if not 0 <= self.bit_length <= 1023 or len(self.data) != (self.bit_length + 7) // 8:
            raise CustodyError("invalid cell size")
        if type(self.refs) is not tuple or len(self.refs) > 4 or any(not isinstance(r, Cell) for r in self.refs):
            raise CustodyError("invalid cell references")
        remainder = self.bit_length % 8
        if remainder and self.data[-1] & ((1 << (8 - remainder)) - 1):
            raise CustodyError("unused cell bits must be zero")

    def prefix(self):
        data = self.data
        if self.bit_length % 8:
            data = data[:-1] + bytes([data[-1] | (1 << (7 - self.bit_length % 8))])
        d2 = self.bit_length // 8 + (self.bit_length + 7) // 8
        return bytes([len(self.refs), d2]) + data

    def commitment(self):
        memo = {}
        active = set()
        def visit(cell, nesting):
            ident = id(cell)
            if nesting > MAX_DEPTH or ident in active:
                raise CustodyError("cell depth or cycle limit exceeded")
            if ident in memo:
                return memo[ident]
            active.add(ident)
            children = [visit(ref, nesting + 1) for ref in cell.refs]
            depth = max((d + 1 for d, _ in children), default=0)
            data = cell.prefix() + b"".join(d.to_bytes(2, "big") for d, _ in children)
            data += b"".join(h for _, h in children)
            result = (depth, sha256(data).digest())
            active.remove(ident)
            memo[ident] = result
            return result
        return visit(self, 0)

    @property
    def hash(self):
        return self.commitment()[1]

    def slice(self):
        return Slice(self)

class Slice:
    def __init__(self, cell):
        self.cell = cell
        self.position = 0
        self.ref_position = 0
        self.value = int.from_bytes(cell.data, "big")

    def uint(self, width):
        if type(width) is not int or width < 0 or self.position + width > self.cell.bit_length:
            raise CustodyError("truncated cell")
        shift = len(self.cell.data) * 8 - self.position - width
        result = (self.value >> shift) & ((1 << width) - 1)
        self.position += width
        return result

    def sint(self, width):
        value = self.uint(width)
        return value - (1 << width) if value & (1 << (width - 1)) else value

    def ref(self):
        if self.ref_position >= len(self.cell.refs):
            raise CustodyError("missing cell reference")
        result = self.cell.refs[self.ref_position]
        self.ref_position += 1
        return result

    def coins(self):
        size = self.uint(4)
        value = self.uint(size * 8)
        if size and value < 1 << ((size - 1) * 8):
            raise CustodyError("noncanonical Coins encoding")
        return value

    def address(self, *, allow_none=False):
        tag = self.uint(2)
        if tag == 0 and allow_none:
            return None
        if tag != 2 or self.uint(1) != 0 or self.sint(8) != 0:
            raise CustodyError("only canonical workchain-0 addresses are supported")
        return "0:" + self.uint(256).to_bytes(32, "big").hex()

    def remainder(self):
        width = self.cell.bit_length - self.position
        value = self.uint(width)
        raw = (value << ((-width) % 8)).to_bytes((width + 7) // 8, "big")
        refs = self.cell.refs[self.ref_position:]
        self.ref_position = len(self.cell.refs)
        return Cell(raw, width, refs)

    def end(self):
        if self.position != self.cell.bit_length or self.ref_position != len(self.cell.refs):
            raise CustodyError("unconsumed bits or references")

def parse_boc(raw):
    if type(raw) is not bytes or not 11 <= len(raw) <= MAX_BYTES or raw[:4] != MAGIC:
        raise CustodyError("invalid BOC magic or size")
    flags, offset_size = raw[4:6]
    size = flags & 7
    if flags & 0x38 or not 1 <= size <= 4 or not 1 <= offset_size <= 4:
        raise CustodyError("unsupported BOC header")
    has_crc, has_index = bool(flags & 0x40), bool(flags & 0x80)
    content = raw[:-4] if has_crc else raw
    if has_crc and crc32c(content) != raw[-4:]:
        raise CustodyError("BOC CRC32C mismatch")
    pos = 6
    def take(n):
        nonlocal pos
        if n < 0 or pos + n > len(content):
            raise CustodyError("truncated BOC")
        data = content[pos:pos + n]
        pos += n
        return data
    def number(n):
        return int.from_bytes(take(n), "big")
    count, roots, absent = number(size), number(size), number(size)
    total = number(offset_size)
    if not 1 <= count <= MAX_CELLS or roots != 1 or absent != 0:
        raise CustodyError("unsupported BOC root/count layout")
    if number(size) != 0:
        raise CustodyError("root must be the first cell")
    index = [number(offset_size) for _ in range(count)] if has_index else None
    if len(content) - pos != total:
        raise CustodyError("BOC data-size mismatch or trailing bytes")
    start = pos
    entries = []
    for i in range(count):
        d1, d2 = number(1), number(1)
        if d1 > 4:
            raise CustodyError("only ordinary level-zero cells are supported")
        data = take((d2 + 1) // 2)
        width = len(data) * 8
        if d2 & 1:
            if not data or data[-1] == 0:
                raise CustodyError("invalid cell termination bit")
            trailing = (data[-1] & -data[-1]).bit_length() - 1
            width -= trailing + 1
            if width % 8 == 0:
                raise CustodyError("noncanonical cell termination")
            data = data[:-1] + bytes([data[-1] & ~(1 << trailing)])
        refs = tuple(number(size) for _ in range(d1))
        if any(not i < ref < count for ref in refs):
            raise CustodyError("references must point strictly forward")
        if index is not None and index[i] != pos - start:
            raise CustodyError("BOC index mismatch")
        entries.append((data, width, refs))
    if pos != len(content):
        raise CustodyError("trailing cell data")
    reachable = {0}
    todo = [0]
    while todo:
        for ref in entries[todo.pop()][2]:
            if ref not in reachable:
                reachable.add(ref)
                todo.append(ref)
    if len(reachable) != count:
        raise CustodyError("unreachable cells")
    built = [None] * count
    depths = [0] * count
    for i in range(count - 1, -1, -1):
        data, width, refs = entries[i]
        depth = max((depths[r] + 1 for r in refs), default=0)
        if depth > MAX_DEPTH:
            raise CustodyError("cell depth limit exceeded")
        depths[i] = depth
        built[i] = Cell(data, width, tuple(built[r] for r in refs))
    return built[0]

def serialize_boc(root, *, crc=False, indexed=False):
    """Deterministic encoder for ordinary-cell fixture/inspection transport."""
    ordered, seen = [], set()
    def visit(cell, depth):
        if depth > MAX_DEPTH:
            raise CustodyError("cell depth limit exceeded")
        if id(cell) in seen:
            return
        seen.add(id(cell))
        if len(seen) > MAX_CELLS:
            raise CustodyError("cell count limit exceeded")
        for ref in cell.refs:
            visit(ref, depth + 1)
        ordered.append(cell)
    visit(root, 0)
    ordered.reverse()
    positions = {id(cell): i for i, cell in enumerate(ordered)}
    size = max(1, (len(ordered).bit_length() + 7) // 8)
    records = [cell.prefix() + b"".join(positions[id(r)].to_bytes(size, "big") for r in cell.refs) for cell in ordered]
    data = b"".join(records)
    offset = max(1, (len(data).bit_length() + 7) // 8)
    flags = size | (0x40 if crc else 0) | (0x80 if indexed else 0)
    header = MAGIC + bytes([flags, offset])
    header += len(ordered).to_bytes(size, "big") + (1).to_bytes(size, "big") + bytes(size)
    header += len(data).to_bytes(offset, "big") + bytes(size)
    if indexed:
        end = 0
        for record in records:
            end += len(record)
            header += end.to_bytes(offset, "big")
    raw = header + data
    raw += crc32c(raw) if crc else b""
    if len(raw) > MAX_BYTES:
        raise CustodyError("BOC size limit exceeded")
    return raw
