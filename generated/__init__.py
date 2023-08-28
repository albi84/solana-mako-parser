# generated from __init__.py.mako
# do not edit manually!
from typing import TYPE_CHECKING
import base58

if TYPE_CHECKING:
    from ..types import Address, Data, RawInstruction

SYSTEM_PROGRAM_ID = "11111111111111111111111111111111"
STAKE_PROGRAM_ID = "Stake11111111111111111111111111111111111111"
COMPUTE_BUDGET_PROGRAM_ID = "ComputeBudget111111111111111111111111111111"
TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"


# TODO SOL: what is this used for?
SYSTEM_TRANSFER_ID = 2

class Instruction:
    program_id: bytes
    accounts: list[Address]
    data: Data

    def __init__(self, raw_instruction: RawInstruction):
        self.program_id, self.accounts, self.data = raw_instruction

    def parse(self) -> None:
        pass

    def validate(self, signer_pub_key: bytes) -> None:
        pass

    async def show(self) -> None:
        # TODO SOL: blind signing could be here?
        pass


async def handle_instructions(
    instructions: list[RawInstruction], signer_pub_key: bytes
) -> None:
    from trezor.crypto import base58
    from trezor.wire import ProcessError

    from .system_program import handle_system_program_instruction
    from .stake_program import handle_stake_program_instruction
    from .compute_budget_program import handle_compute_budget_program_instruction
    from .token_program import handle_token_program_instruction

    for instruction in instructions:
        program_id, _, _ = instruction

        encoded_program_id = base58.encode(program_id)

        if SYSTEM_PROGRAM_ID == encoded_program_id:
            await handle_system_program_instruction(instruction, signer_pub_key)
        elif STAKE_PROGRAM_ID == encoded_program_id:
            await handle_stake_program_instruction(instruction, signer_pub_key)
        elif COMPUTE_BUDGET_PROGRAM_ID == encoded_program_id:
            await handle_compute_budget_program_instruction(instruction, signer_pub_key)
        elif TOKEN_PROGRAM_ID == encoded_program_id:
            await handle_token_program_instruction(instruction, signer_pub_key)
        else:
            # TODO SOL: blind signing for unknown programs
            raise ProcessError(f"Unknown program id: {encoded_program_id}")
