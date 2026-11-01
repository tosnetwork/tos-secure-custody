"""Synthetic public fixture builder. Contains no production account or secret."""
from tos_custody.boc import Cell, serialize_boc

NOW = 1793491200
VAULT = "0:" + "11" * 32
BUSINESS = "0:" + "22" * 32
RECIPIENT = "0:" + "33" * 32
COLD = "0:" + "44" * 32
GUARDIAN = "0:" + "55" * 32
PAUSER = "0:" + "66" * 32
NETWORK = -777777

class Builder:
    def __init__(self):
        self.bits = ""
        self.refs = []
    def u(self, value, width):
        if not 0 <= value < 1 << width:
            raise ValueError("fixture integer out of range")
        self.bits += format(value, f"0{width}b") if width else ""
        return self
    def s(self, value, width):
        return self.u(value % (1 << width), width)
    def addr(self, address):
        if address is None:
            return self.u(0, 2)
        return self.u(4, 3).s(0, 8).u(int(address[2:], 16), 256)
    def coins(self, value):
        size = (value.bit_length() + 7) // 8
        return self.u(size, 4).u(value, size * 8)
    def ref(self, value):
        self.refs.append(value)
        return self
    def cell(self):
        width = len(self.bits)
        data = (int(self.bits or "0", 2) << ((-width) % 8)).to_bytes((width + 7) // 8, "big")
        return Cell(data, width, tuple(self.refs))


def payload(*, asset=0, amount=1_000_000_000, recipient=RECIPIENT, attachment=0):
    return Builder().u(asset, 256).coins(amount).addr(recipient).coins(attachment).cell()


def request(*, pay=None, admin=False, network=NETWORK, vault=VAULT, epoch=7, nonce=42, deadline=NOW + 300):
    return (Builder().u(0x54564731 if admin else 0x54565031, 32).s(network, 32).addr(vault)
            .u(epoch, 64).u(nonce, 64).u(deadline, 32).ref(pay or payload()).cell())


def body(*, op=0x54560001, req=None, epoch=7, nonce=42):
    result = Builder().u(op, 32).u(0, 64)
    if op in (0x54560001, 0x54560002, 0x54560006, 0x54560007):
        result.ref(req or request())
    else:
        result.u(epoch, 64).u(nonce, 64)
    return result.cell()


def internal(*, message_body=None, source=BUSINESS, destination=VAULT, value=100_000_000,
             state_init=False, bounced=False, inline=False):
    b = (Builder().u(0, 1).u(1, 1).u(1, 1).u(int(bounced), 1).addr(source).addr(destination)
         .coins(value).u(0, 1).coins(0).coins(0).u(0, 64).u(0, 32).u(int(state_init), 1))
    content = message_body or body()
    if state_init:
        b.u(1, 1).ref(Builder().cell())
    b.u(0 if inline else 1, 1)
    if inline:
        bits = ''.join(f"{x:08b}" for x in content.data)[:content.bit_length]
        b.bits += bits
        b.refs.extend(content.refs)
    else:
        b.ref(content)
    return b.cell()


def policy():
    return {"schema": "tos.custody.diagnostic-policy.v1", "network_global_id": NETWORK,
            "vault": VAULT, "epoch": 7, "next_nonce": 42, "operation": "submit",
            "expected_role": BUSINESS, "max_control_value": 200_000_000,
            "valid_until": NOW + 3600,
            "assets": {"0" * 64: {"max_payment": 2_000_000_000,
                                   "recipients": [RECIPIENT], "max_token_attachment": 0}}}


def bundle(cell=None):
    return {"schema": "tos.custody.offline-inspection.v1",
            "boc_hex": serialize_boc(cell or internal()).hex()}
