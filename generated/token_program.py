# generated from program.py.mako
# do not edit manually!

from typing import TYPE_CHECKING

from trezor.crypto import base58
from trezor.enums import ButtonRequestType
from trezor.strings import format_amount
from trezor.ui.layouts import confirm_output, confirm_properties
from trezor.wire import ProcessError

from ..constants import ADDRESS_RW, ADDRESS_SIG, ADDRESS_SIG_READ_ONLY
from . import TOKEN_PROGRAM_ID, Instruction

if TYPE_CHECKING:
    from typing import Awaitable

    from ..types import RawInstruction


def handle_token_program_instruction(
    raw_instruction: RawInstruction, signer_pub_key: bytes
) -> Awaitable[None]:
    program_id, _, _ = raw_instruction
    assert base58.encode(program_id) == TOKEN_PROGRAM_ID

    instruction = _get_instruction(raw_instruction)

    instruction.parse()
    instruction.validate(signer_pub_key)
    return instruction.show()


def _get_instruction(raw_instruction: RawInstruction) -> Instruction:
    _, _, data = raw_instruction

    assert data.remaining_count() >= 4
    instruction_id = int.from_bytes(data.read(4), "little")
    data.seek(0)

    else:
        # TODO SOL: blind signing
        raise ProcessError("Unknown system program instruction")

