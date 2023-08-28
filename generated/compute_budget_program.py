# generated from program.py.mako
# do not edit manually!

from typing import TYPE_CHECKING

from trezor.crypto import base58
from trezor.enums import ButtonRequestType
from trezor.strings import format_amount
from trezor.ui.layouts import confirm_output, confirm_properties
from trezor.wire import ProcessError

from ..constants import ADDRESS_RW, ADDRESS_SIG, ADDRESS_SIG_READ_ONLY
from . import COMPUTE_BUDGET_PROGRAM_ID, Instruction

if TYPE_CHECKING:
    from typing import Awaitable

    from ..types import RawInstruction

INS_REQUEST_HEAP_FRAME = 1
INS_SET_COMPUTE_UNIT_LIMIT = 2
INS_SET_COMPUTE_UNIT_PRICE = 3

def handle_compute_budget_program_instruction(
    raw_instruction: RawInstruction, signer_pub_key: bytes
) -> Awaitable[None]:
    program_id, _, _ = raw_instruction
    assert base58.encode(program_id) == COMPUTE_BUDGET_PROGRAM_ID

    instruction = _get_instruction(raw_instruction)

    instruction.parse()
    instruction.validate(signer_pub_key)
    return instruction.show()


def _get_instruction(raw_instruction: RawInstruction) -> Instruction:
    _, _, data = raw_instruction

    assert data.remaining_count() >= 4
    instruction_id = int.from_bytes(data.read(4), "little")
    data.seek(0)

    if INS_REQUEST_HEAP_FRAME == instruction_id:
        return RequestHeapFrameInstruction(raw_instruction)
    elif INS_SET_COMPUTE_UNIT_LIMIT == instruction_id:
        return SetComputeUnitLimitInstruction(raw_instruction)
    elif INS_SET_COMPUTE_UNIT_PRICE == instruction_id:
        return SetComputeUnitPriceInstruction(raw_instruction)
    else:
        # TODO SOL: blind signing
        raise ProcessError("Unknown system program instruction")

class RequestHeapFrameInstruction(Instruction):
    PROGRAM_ID = COMPUTE_BUDGET_PROGRAM_ID
    INSTRUCTION_ID = INS_REQUEST_HEAP_FRAME

    bytes: int


    def get_data_template(self) -> list[tuple]:
        return [
            ("bytes", "u32"),
        ]

    def get_accounts_template(self) -> list[tuple[str, int]]:
        return [
        ]

    def validate(self, signer_pub_key: bytes) -> None:
        if self.funding_account != signer_pub_key:
            raise ProcessError("Invalid funding account")

    def show(self) -> Awaitable[None]:
        props = [
            ("Bytes", str(self.bytes)),
        ]

        return confirm_properties("request_heap_frame", "Request Heap Frame", props)

class SetComputeUnitLimitInstruction(Instruction):
    PROGRAM_ID = COMPUTE_BUDGET_PROGRAM_ID
    INSTRUCTION_ID = INS_SET_COMPUTE_UNIT_LIMIT

    units: int


    def get_data_template(self) -> list[tuple]:
        return [
            ("units", "u32"),
        ]

    def get_accounts_template(self) -> list[tuple[str, int]]:
        return [
        ]

    def validate(self, signer_pub_key: bytes) -> None:
        if self.funding_account != signer_pub_key:
            raise ProcessError("Invalid funding account")

    def show(self) -> Awaitable[None]:
        props = [
            ("Units", str(self.units)),
        ]

        return confirm_properties("set_compute_unit_limit", "Set Compute Unit Limit", props)

class SetComputeUnitPriceInstruction(Instruction):
    PROGRAM_ID = COMPUTE_BUDGET_PROGRAM_ID
    INSTRUCTION_ID = INS_SET_COMPUTE_UNIT_PRICE

    lamports: int


    def get_data_template(self) -> list[tuple]:
        return [
            ("lamports", "u64"),
        ]

    def get_accounts_template(self) -> list[tuple[str, int]]:
        return [
        ]

    def validate(self, signer_pub_key: bytes) -> None:
        if self.funding_account != signer_pub_key:
            raise ProcessError("Invalid funding account")

    def show(self) -> Awaitable[None]:
        props = [
            ("Lamports", str(self.lamports)),
        ]

        return confirm_properties("set_compute_unit_price", "Set Compute Unit Price", props)

