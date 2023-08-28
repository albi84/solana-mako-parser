# generated from program.py.mako
# do not edit manually!

from typing import TYPE_CHECKING

from trezor.crypto import base58
from trezor.enums import ButtonRequestType
from trezor.strings import format_amount
from trezor.ui.layouts import confirm_output, confirm_properties
from trezor.wire import ProcessError

from ..constants import ADDRESS_RW, ADDRESS_SIG, ADDRESS_SIG_READ_ONLY
from . import SYSTEM_PROGRAM_ID, Instruction

if TYPE_CHECKING:
    from typing import Awaitable

    from ..types import RawInstruction

INS_CREATE_ACCOUNT = 0
INS_ASSIGN = 1
INS_TRANSFER = 2
INS_CREATE_ACCOUNT_WITH_SEED = 3
INS_ALLOCATE = 8
INS_ALLOCATE_WITH_SEED = 9
INS_ASSIGN_WITH_SEED = 10

def handle_system_program_instruction(
    raw_instruction: RawInstruction, signer_pub_key: bytes
) -> Awaitable[None]:
    program_id, _, _ = raw_instruction
    assert base58.encode(program_id) == SYSTEM_PROGRAM_ID

    instruction = _get_instruction(raw_instruction)

    instruction.parse()
    instruction.validate(signer_pub_key)
    return instruction.show()


def _get_instruction(raw_instruction: RawInstruction) -> Instruction:
    _, _, data = raw_instruction

    assert data.remaining_count() >= 4
    instruction_id = int.from_bytes(data.read(4), "little")
    data.seek(0)

    if INS_CREATE_ACCOUNT == instruction_id:
        return CreateAccountInstruction(raw_instruction)
    elif INS_ASSIGN == instruction_id:
        return AssignInstruction(raw_instruction)
    elif INS_TRANSFER == instruction_id:
        return TransferInstruction(raw_instruction)
    elif INS_CREATE_ACCOUNT_WITH_SEED == instruction_id:
        return CreateAccountWithSeedInstruction(raw_instruction)
    elif INS_ALLOCATE == instruction_id:
        return AllocateInstruction(raw_instruction)
    elif INS_ALLOCATE_WITH_SEED == instruction_id:
        return AllocateWithSeedInstruction(raw_instruction)
    elif INS_ASSIGN_WITH_SEED == instruction_id:
        return AssignWithSeedInstruction(raw_instruction)
    else:
        # TODO SOL: blind signing
        raise ProcessError("Unknown system program instruction")

class CreateAccountInstruction(Instruction):
    PROGRAM_ID = SYSTEM_PROGRAM_ID
    INSTRUCTION_ID = INS_CREATE_ACCOUNT

    lamports: int
    space: int
    owner: bytes

    funding_account: bytes 
    new_account: bytes 

    def get_data_template(self) -> list[tuple]:
        return [
            ("lamports", "u64"),
            ("space", "u64"),
            ("owner", "pubkey"),
        ]

    def get_accounts_template(self) -> list[tuple[str, int]]:
        return [
            ("funding_account", ADDRESS_SIG),
            ("new_account", ADDRESS_SIG),
        ]

    def validate(self, signer_pub_key: bytes) -> None:
        if self.funding_account != signer_pub_key:
            raise ProcessError("Invalid funding account")

    def show(self) -> Awaitable[None]:
        props = [
            ("Lamports", str(self.lamports)),
            ("Space", str(self.space)),
            ("Owner", base58.encode(self.owner)),
            ("Funding account", base58.encode(self.funding_account)),
            ("New account", base58.encode(self.new_account)),
        ]

        return confirm_properties("create_account", "Create Account", props)

class AssignInstruction(Instruction):
    PROGRAM_ID = SYSTEM_PROGRAM_ID
    INSTRUCTION_ID = INS_ASSIGN

    owner: bytes

    assigned_account: bytes 

    def get_data_template(self) -> list[tuple]:
        return [
            ("owner", "pubkey"),
        ]

    def get_accounts_template(self) -> list[tuple[str, int]]:
        return [
            ("assigned_account", ADDRESS_SIG),
        ]

    def validate(self, signer_pub_key: bytes) -> None:
        if self.funding_account != signer_pub_key:
            raise ProcessError("Invalid funding account")

    def show(self) -> Awaitable[None]:
        props = [
            ("Owner", base58.encode(self.owner)),
            ("Assigned account", base58.encode(self.assigned_account)),
        ]

        return confirm_properties("assign", "Assign", props)

class TransferInstruction(Instruction):
    PROGRAM_ID = SYSTEM_PROGRAM_ID
    INSTRUCTION_ID = INS_TRANSFER

    lamports: int

    funding_account: bytes 
    recipient_account: bytes 

    def get_data_template(self) -> list[tuple]:
        return [
            ("lamports", "u64"),
        ]

    def get_accounts_template(self) -> list[tuple[str, int]]:
        return [
            ("funding_account", ADDRESS_SIG),
            ("recipient_account", ADDRESS_RW),
        ]

    def validate(self, signer_pub_key: bytes) -> None:
        if self.funding_account != signer_pub_key:
            raise ProcessError("Invalid funding account")

    def show(self) -> Awaitable[None]:
        props = [
            ("Lamports", str(self.lamports)),
            ("Funding account", base58.encode(self.funding_account)),
            ("Recipient account", base58.encode(self.recipient_account)),
        ]

        return confirm_properties("transfer", "Transfer", props)

class CreateAccountWithSeedInstruction(Instruction):
    PROGRAM_ID = SYSTEM_PROGRAM_ID
    INSTRUCTION_ID = INS_CREATE_ACCOUNT_WITH_SEED

    base: bytes
    seed: str
    lamports: int
    space: int
    owner: bytes

    funding_account: bytes 
    created_account: bytes 
    base_account: bytes | None


    def get_data_template(self) -> list[tuple]:
        return [
            ("base", "pubkey"),
            ("seed", "string"),
            ("lamports", "u64"),
            ("space", "u64"),
            ("owner", "pubkey"),
        ]

    def get_accounts_template(self) -> list[tuple[str, int]]:
        return [
            ("funding_account", ADDRESS_SIG),
            ("created_account", ADDRESS_SIG),
            ("base_account", ADDRESS_SIG_READ_ONLY, True),
        ]

    def validate(self, signer_pub_key: bytes) -> None:
        if self.funding_account != signer_pub_key:
            raise ProcessError("Invalid funding account")

    def show(self) -> Awaitable[None]:
        props = [
            ("Base", base58.encode(self.base)),
            ("Seed", str(self.seed)),
            ("Lamports", str(self.lamports)),
            ("Space", str(self.space)),
            ("Owner", base58.encode(self.owner)),
            ("Funding account", base58.encode(self.funding_account)),
            ("Created account", base58.encode(self.created_account)),
        ]
        if self.base_account is not None:
            props.append(("Base account", base58.encode(self.base_account)))    

        return confirm_properties("create_account_with_seed", "Create Account With Seed", props)

class AllocateInstruction(Instruction):
    PROGRAM_ID = SYSTEM_PROGRAM_ID
    INSTRUCTION_ID = INS_ALLOCATE

    space: int

    new_account: bytes 

    def get_data_template(self) -> list[tuple]:
        return [
            ("space", "u64"),
        ]

    def get_accounts_template(self) -> list[tuple[str, int]]:
        return [
            ("new_account", ADDRESS_SIG),
        ]

    def validate(self, signer_pub_key: bytes) -> None:
        if self.funding_account != signer_pub_key:
            raise ProcessError("Invalid funding account")

    def show(self) -> Awaitable[None]:
        props = [
            ("Space", str(self.space)),
            ("New account", base58.encode(self.new_account)),
        ]

        return confirm_properties("allocate", "Allocate", props)

class AllocateWithSeedInstruction(Instruction):
    PROGRAM_ID = SYSTEM_PROGRAM_ID
    INSTRUCTION_ID = INS_ALLOCATE_WITH_SEED

    base: bytes
    seed: str
    space: int
    owner: bytes

    allocated_account: bytes 
    base_account: bytes 

    def get_data_template(self) -> list[tuple]:
        return [
            ("base", "pubkey"),
            ("seed", "string"),
            ("space", "u64"),
            ("owner", "pubkey"),
        ]

    def get_accounts_template(self) -> list[tuple[str, int]]:
        return [
            ("allocated_account", ADDRESS_RW),
            ("base_account", ADDRESS_SIG_READ_ONLY),
        ]

    def validate(self, signer_pub_key: bytes) -> None:
        if self.funding_account != signer_pub_key:
            raise ProcessError("Invalid funding account")

    def show(self) -> Awaitable[None]:
        props = [
            ("Base", base58.encode(self.base)),
            ("Seed", str(self.seed)),
            ("Space", str(self.space)),
            ("Owner", base58.encode(self.owner)),
            ("Allocated account", base58.encode(self.allocated_account)),
            ("Base account", base58.encode(self.base_account)),
        ]

        return confirm_properties("allocate_with_seed", "Allocate With Seed", props)

class AssignWithSeedInstruction(Instruction):
    PROGRAM_ID = SYSTEM_PROGRAM_ID
    INSTRUCTION_ID = INS_ASSIGN_WITH_SEED

    base: bytes
    seed: str
    owner: bytes

    assigned_account: bytes 
    base_account: bytes 

    def get_data_template(self) -> list[tuple]:
        return [
            ("base", "pubkey"),
            ("seed", "string"),
            ("owner", "pubkey"),
        ]

    def get_accounts_template(self) -> list[tuple[str, int]]:
        return [
            ("assigned_account", ADDRESS_RW),
            ("base_account", ADDRESS_SIG_READ_ONLY),
        ]

    def validate(self, signer_pub_key: bytes) -> None:
        if self.funding_account != signer_pub_key:
            raise ProcessError("Invalid funding account")

    def show(self) -> Awaitable[None]:
        props = [
            ("Base", base58.encode(self.base)),
            ("Seed", str(self.seed)),
            ("Owner", base58.encode(self.owner)),
            ("Assigned account", base58.encode(self.assigned_account)),
            ("Base account", base58.encode(self.base_account)),
        ]

        return confirm_properties("assign_with_seed", "Assign With Seed", props)

