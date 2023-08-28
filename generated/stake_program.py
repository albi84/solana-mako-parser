# generated from program.py.mako
# do not edit manually!

from typing import TYPE_CHECKING

from trezor.crypto import base58
from trezor.enums import ButtonRequestType
from trezor.strings import format_amount
from trezor.ui.layouts import confirm_output, confirm_properties
from trezor.wire import ProcessError

from ..constants import ADDRESS_RW, ADDRESS_SIG, ADDRESS_SIG_READ_ONLY
from . import STAKE_PROGRAM_ID, Instruction

if TYPE_CHECKING:
    from typing import Awaitable

    from ..types import RawInstruction

INS_INITIALIZE = 0
INS_AUTHORIZE = 1
INS_DELEGATE_STAKE = 2
INS_SPLIT = 3
INS_WITHDRAW = 4
INS_DEACTIVATE = 5
INS_SET_LOCKUP = 6
INS_MERGE = 7
INS_AUTHORIZE_WITH_SEED = 8
INS_INITIALIZE_CHECKED = 9
INS_AUTHORIZE_CHECKED = 10
INS_AUTHORIZE_CHECKED_WITH_SEED = 11
INS_SET_LOCKUP_CHECKED = 12

def handle_stake_program_instruction(
    raw_instruction: RawInstruction, signer_pub_key: bytes
) -> Awaitable[None]:
    program_id, _, _ = raw_instruction
    assert base58.encode(program_id) == STAKE_PROGRAM_ID

    instruction = _get_instruction(raw_instruction)

    instruction.parse()
    instruction.validate(signer_pub_key)
    return instruction.show()


def _get_instruction(raw_instruction: RawInstruction) -> Instruction:
    _, _, data = raw_instruction

    assert data.remaining_count() >= 4
    instruction_id = int.from_bytes(data.read(4), "little")
    data.seek(0)

    if INS_INITIALIZE == instruction_id:
        return InitializeInstruction(raw_instruction)
    elif INS_AUTHORIZE == instruction_id:
        return AuthorizeInstruction(raw_instruction)
    elif INS_DELEGATE_STAKE == instruction_id:
        return DelegateStakeInstruction(raw_instruction)
    elif INS_SPLIT == instruction_id:
        return SplitInstruction(raw_instruction)
    elif INS_WITHDRAW == instruction_id:
        return WithdrawInstruction(raw_instruction)
    elif INS_DEACTIVATE == instruction_id:
        return DeactivateInstruction(raw_instruction)
    elif INS_SET_LOCKUP == instruction_id:
        return SetLockupInstruction(raw_instruction)
    elif INS_MERGE == instruction_id:
        return MergeInstruction(raw_instruction)
    elif INS_AUTHORIZE_WITH_SEED == instruction_id:
        return AuthorizeWithSeedInstruction(raw_instruction)
    elif INS_INITIALIZE_CHECKED == instruction_id:
        return InitializeCheckedInstruction(raw_instruction)
    elif INS_AUTHORIZE_CHECKED == instruction_id:
        return AuthorizeCheckedInstruction(raw_instruction)
    elif INS_AUTHORIZE_CHECKED_WITH_SEED == instruction_id:
        return AuthorizeCheckedWithSeedInstruction(raw_instruction)
    elif INS_SET_LOCKUP_CHECKED == instruction_id:
        return SetLockupCheckedInstruction(raw_instruction)
    else:
        # TODO SOL: blind signing
        raise ProcessError("Unknown system program instruction")

class InitializeInstruction(Instruction):
    PROGRAM_ID = STAKE_PROGRAM_ID
    INSTRUCTION_ID = INS_INITIALIZE

    staker: bytes
    withdrawer: bytes
    unix_timestamp: int
    epoch: int
    custodian: bytes

    uninitialized_stake_account: bytes 
    rent_sysvar: bytes 

    def get_data_template(self) -> list[tuple]:
        return [
            ("staker", "pubkey"),
            ("withdrawer", "pubkey"),
            ("unix_timestamp", "i64"),
            ("epoch", "u64"),
            ("custodian", "pubkey"),
        ]

    def get_accounts_template(self) -> list[tuple[str, int]]:
        return [
            ("uninitialized_stake_account", ADDRESS_RW),
            ("rent_sysvar", ADDRESS_READ_ONLY),
        ]

    def validate(self, signer_pub_key: bytes) -> None:
        if self.funding_account != signer_pub_key:
            raise ProcessError("Invalid funding account")

    def show(self) -> Awaitable[None]:
        props = [
            ("Staker", base58.encode(self.staker)),
            ("Withdrawer", base58.encode(self.withdrawer)),
            ("Unix_timestamp", str(self.unix_timestamp)),
            ("Epoch", str(self.epoch)),
            ("Custodian", base58.encode(self.custodian)),
            ("Uninitialized stake account", base58.encode(self.uninitialized_stake_account)),
            ("Rent sysvar", base58.encode(self.rent_sysvar)),
        ]

        return confirm_properties("initialize", "Initialize", props)

class AuthorizeInstruction(Instruction):
    PROGRAM_ID = STAKE_PROGRAM_ID
    INSTRUCTION_ID = INS_AUTHORIZE

    pubkey: bytes
    stakeauthorize: int

    stake_account: bytes 
    clock_sysvar: bytes 
    stake_or_withdraw_authority: bytes 
    lockup_authority: bytes | None


    def get_data_template(self) -> list[tuple]:
        return [
            ("pubkey", "pubkey"),
            ("stakeauthorize", "stakeauthorize"),
        ]

    def get_accounts_template(self) -> list[tuple[str, int]]:
        return [
            ("stake_account", ADDRESS_RW),
            ("clock_sysvar", ADDRESS_READ_ONLY),
            ("stake_or_withdraw_authority", ADDRESS_SIG_READ_ONLY),
            ("lockup_authority", ADDRESS_SIG_READ_ONLY, True),
        ]

    def validate(self, signer_pub_key: bytes) -> None:
        if self.funding_account != signer_pub_key:
            raise ProcessError("Invalid funding account")

    def show(self) -> Awaitable[None]:
        props = [
            ("Pubkey", base58.encode(self.pubkey)),
            ("Stakeauthorize", str(self.stakeauthorize)),
            ("Stake account", base58.encode(self.stake_account)),
            ("Clock sysvar", base58.encode(self.clock_sysvar)),
            ("Stake or withdraw authority", base58.encode(self.stake_or_withdraw_authority)),
        ]
        if self.lockup_authority is not None:
            props.append(("Lockup authority", base58.encode(self.lockup_authority)))    

        return confirm_properties("authorize", "Authorize", props)

class DelegateStakeInstruction(Instruction):
    PROGRAM_ID = STAKE_PROGRAM_ID
    INSTRUCTION_ID = INS_DELEGATE_STAKE


    initialized_stake_account: bytes 
    vote_account: bytes 
    clock_sysvar: bytes 
    stake_history_sysvar: bytes 
    config_account: bytes 
    stake_authority: bytes 

    def get_data_template(self) -> list[tuple]:
        return [
        ]

    def get_accounts_template(self) -> list[tuple[str, int]]:
        return [
            ("initialized_stake_account", ADDRESS_RW),
            ("vote_account", ADDRESS_READ_ONLY),
            ("clock_sysvar", ADDRESS_READ_ONLY),
            ("stake_history_sysvar", ADDRESS_READ_ONLY),
            ("config_account", ADDRESS_READ_ONLY),
            ("stake_authority", ADDRESS_SIG_READ_ONLY),
        ]

    def validate(self, signer_pub_key: bytes) -> None:
        if self.funding_account != signer_pub_key:
            raise ProcessError("Invalid funding account")

    def show(self) -> Awaitable[None]:
        props = [
            ("Initialized stake account", base58.encode(self.initialized_stake_account)),
            ("Vote account", base58.encode(self.vote_account)),
            ("Clock sysvar", base58.encode(self.clock_sysvar)),
            ("Stake history sysvar", base58.encode(self.stake_history_sysvar)),
            ("Config account", base58.encode(self.config_account)),
            ("Stake authority", base58.encode(self.stake_authority)),
        ]

        return confirm_properties("delegate_stake", "Delegate Stake", props)

class SplitInstruction(Instruction):
    PROGRAM_ID = STAKE_PROGRAM_ID
    INSTRUCTION_ID = INS_SPLIT

    lamports: int

    stake_account: bytes 
    uninitialized_stake_account: bytes 
    stake_authority: bytes 

    def get_data_template(self) -> list[tuple]:
        return [
            ("lamports", "u64"),
        ]

    def get_accounts_template(self) -> list[tuple[str, int]]:
        return [
            ("stake_account", ADDRESS_RW),
            ("uninitialized_stake_account", ADDRESS_RW),
            ("stake_authority", ADDRESS_SIG_READ_ONLY),
        ]

    def validate(self, signer_pub_key: bytes) -> None:
        if self.funding_account != signer_pub_key:
            raise ProcessError("Invalid funding account")

    def show(self) -> Awaitable[None]:
        props = [
            ("Lamports", str(self.lamports)),
            ("Stake account", base58.encode(self.stake_account)),
            ("Uninitialized stake account", base58.encode(self.uninitialized_stake_account)),
            ("Stake authority", base58.encode(self.stake_authority)),
        ]

        return confirm_properties("split", "Split", props)

class WithdrawInstruction(Instruction):
    PROGRAM_ID = STAKE_PROGRAM_ID
    INSTRUCTION_ID = INS_WITHDRAW

    lamports: int

    stake_account: bytes 
    recipient_account: bytes 
    clock_sysvar: bytes 
    stake_history_sysvar: bytes 
    withdraw_authority: bytes 
    lockup_authority: bytes | None


    def get_data_template(self) -> list[tuple]:
        return [
            ("lamports", "u64"),
        ]

    def get_accounts_template(self) -> list[tuple[str, int]]:
        return [
            ("stake_account", ADDRESS_RW),
            ("recipient_account", ADDRESS_RW),
            ("clock_sysvar", ADDRESS_READ_ONLY),
            ("stake_history_sysvar", ADDRESS_READ_ONLY),
            ("withdraw_authority", ADDRESS_SIG_READ_ONLY),
            ("lockup_authority", ADDRESS_SIG_READ_ONLY, True),
        ]

    def validate(self, signer_pub_key: bytes) -> None:
        if self.funding_account != signer_pub_key:
            raise ProcessError("Invalid funding account")

    def show(self) -> Awaitable[None]:
        props = [
            ("Lamports", str(self.lamports)),
            ("Stake account", base58.encode(self.stake_account)),
            ("Recipient account", base58.encode(self.recipient_account)),
            ("Clock sysvar", base58.encode(self.clock_sysvar)),
            ("Stake history sysvar", base58.encode(self.stake_history_sysvar)),
            ("Withdraw authority", base58.encode(self.withdraw_authority)),
        ]
        if self.lockup_authority is not None:
            props.append(("Lockup authority", base58.encode(self.lockup_authority)))    

        return confirm_properties("withdraw", "Withdraw", props)

class DeactivateInstruction(Instruction):
    PROGRAM_ID = STAKE_PROGRAM_ID
    INSTRUCTION_ID = INS_DEACTIVATE


    delegated_stake_account: bytes 
    clock_sysvar: bytes 
    stake_authority: bytes 

    def get_data_template(self) -> list[tuple]:
        return [
        ]

    def get_accounts_template(self) -> list[tuple[str, int]]:
        return [
            ("delegated_stake_account", ADDRESS_RW),
            ("clock_sysvar", ADDRESS_READ_ONLY),
            ("stake_authority", ADDRESS_SIG_READ_ONLY),
        ]

    def validate(self, signer_pub_key: bytes) -> None:
        if self.funding_account != signer_pub_key:
            raise ProcessError("Invalid funding account")

    def show(self) -> Awaitable[None]:
        props = [
            ("Delegated stake account", base58.encode(self.delegated_stake_account)),
            ("Clock sysvar", base58.encode(self.clock_sysvar)),
            ("Stake authority", base58.encode(self.stake_authority)),
        ]

        return confirm_properties("deactivate", "Deactivate", props)

class SetLockupInstruction(Instruction):
    PROGRAM_ID = STAKE_PROGRAM_ID
    INSTRUCTION_ID = INS_SET_LOCKUP

    unix_timestamp: int
    epoch: int
    custodian: bytes

    initialized_stake_account: bytes 
    lockup_authority_or_withdraw_authority: bytes 

    def get_data_template(self) -> list[tuple]:
        return [
            ("unix_timestamp", "i64"),
            ("epoch", "u64"),
            ("custodian", "pubkey"),
        ]

    def get_accounts_template(self) -> list[tuple[str, int]]:
        return [
            ("initialized_stake_account", ADDRESS_RW),
            ("lockup_authority_or_withdraw_authority", ADDRESS_SIG_READ_ONLY),
        ]

    def validate(self, signer_pub_key: bytes) -> None:
        if self.funding_account != signer_pub_key:
            raise ProcessError("Invalid funding account")

    def show(self) -> Awaitable[None]:
        props = [
            ("Unix_timestamp", str(self.unix_timestamp)),
            ("Epoch", str(self.epoch)),
            ("Custodian", base58.encode(self.custodian)),
            ("Initialized stake account", base58.encode(self.initialized_stake_account)),
            ("Lockup authority or withdraw authority", base58.encode(self.lockup_authority_or_withdraw_authority)),
        ]

        return confirm_properties("set_lockup", "Set Lockup", props)

class MergeInstruction(Instruction):
    PROGRAM_ID = STAKE_PROGRAM_ID
    INSTRUCTION_ID = INS_MERGE


    destination_stake_account: bytes 
    source_stake_account: bytes 
    clock_sysvar: bytes 
    stake_history_sysvar: bytes 
    stake_authority: bytes 

    def get_data_template(self) -> list[tuple]:
        return [
        ]

    def get_accounts_template(self) -> list[tuple[str, int]]:
        return [
            ("destination_stake_account", ADDRESS_RW),
            ("source_stake_account", ADDRESS_RW),
            ("clock_sysvar", ADDRESS_READ_ONLY),
            ("stake_history_sysvar", ADDRESS_READ_ONLY),
            ("stake_authority", ADDRESS_SIG_READ_ONLY),
        ]

    def validate(self, signer_pub_key: bytes) -> None:
        if self.funding_account != signer_pub_key:
            raise ProcessError("Invalid funding account")

    def show(self) -> Awaitable[None]:
        props = [
            ("Destination stake account", base58.encode(self.destination_stake_account)),
            ("Source stake account", base58.encode(self.source_stake_account)),
            ("Clock sysvar", base58.encode(self.clock_sysvar)),
            ("Stake history sysvar", base58.encode(self.stake_history_sysvar)),
            ("Stake authority", base58.encode(self.stake_authority)),
        ]

        return confirm_properties("merge", "Merge", props)

class AuthorizeWithSeedInstruction(Instruction):
    PROGRAM_ID = STAKE_PROGRAM_ID
    INSTRUCTION_ID = INS_AUTHORIZE_WITH_SEED

    new_authorized_pubkey: bytes
    stake_authorize: int
    authority_seed: str
    authority_owner: bytes

    stake_account: bytes 
    stake_or_withdraw_authority: bytes 
    clock_sysvar: bytes 
    lockup_authority: bytes | None


    def get_data_template(self) -> list[tuple]:
        return [
            ("new_authorized_pubkey", "pubkey"),
            ("stake_authorize", "stakeauthorize"),
            ("authority_seed", "string"),
            ("authority_owner", "pubkey"),
        ]

    def get_accounts_template(self) -> list[tuple[str, int]]:
        return [
            ("stake_account", ADDRESS_RW),
            ("stake_or_withdraw_authority", ADDRESS_SIG_READ_ONLY),
            ("clock_sysvar", ADDRESS_READ_ONLY),
            ("lockup_authority", ADDRESS_SIG_READ_ONLY, True),
        ]

    def validate(self, signer_pub_key: bytes) -> None:
        if self.funding_account != signer_pub_key:
            raise ProcessError("Invalid funding account")

    def show(self) -> Awaitable[None]:
        props = [
            ("New_authorized_pubkey", base58.encode(self.new_authorized_pubkey)),
            ("Stake_authorize", str(self.stake_authorize)),
            ("Authority_seed", str(self.authority_seed)),
            ("Authority_owner", base58.encode(self.authority_owner)),
            ("Stake account", base58.encode(self.stake_account)),
            ("Stake or withdraw authority", base58.encode(self.stake_or_withdraw_authority)),
            ("Clock sysvar", base58.encode(self.clock_sysvar)),
        ]
        if self.lockup_authority is not None:
            props.append(("Lockup authority", base58.encode(self.lockup_authority)))    

        return confirm_properties("authorize_with_seed", "Authorize With Seed", props)

class InitializeCheckedInstruction(Instruction):
    PROGRAM_ID = STAKE_PROGRAM_ID
    INSTRUCTION_ID = INS_INITIALIZE_CHECKED


    uninitialized_stake_account: bytes 
    rent_sysvar: bytes 
    stake_authority: bytes 
    withdraw_authority: bytes 

    def get_data_template(self) -> list[tuple]:
        return [
        ]

    def get_accounts_template(self) -> list[tuple[str, int]]:
        return [
            ("uninitialized_stake_account", ADDRESS_RW),
            ("rent_sysvar", ADDRESS_READ_ONLY),
            ("stake_authority", ADDRESS_READ_ONLY),
            ("withdraw_authority", ADDRESS_SIG_READ_ONLY),
        ]

    def validate(self, signer_pub_key: bytes) -> None:
        if self.funding_account != signer_pub_key:
            raise ProcessError("Invalid funding account")

    def show(self) -> Awaitable[None]:
        props = [
            ("Uninitialized stake account", base58.encode(self.uninitialized_stake_account)),
            ("Rent sysvar", base58.encode(self.rent_sysvar)),
            ("Stake authority", base58.encode(self.stake_authority)),
            ("Withdraw authority", base58.encode(self.withdraw_authority)),
        ]

        return confirm_properties("initialize_checked", "Initialize Checked", props)

class AuthorizeCheckedInstruction(Instruction):
    PROGRAM_ID = STAKE_PROGRAM_ID
    INSTRUCTION_ID = INS_AUTHORIZE_CHECKED

    stakeauthorize: int

    stake_account: bytes 
    clock_sysvar: bytes 
    stake_or_withdraw_authority: bytes 
    new_stake_or_withdraw_authority: bytes 
    lockup_authority: bytes | None


    def get_data_template(self) -> list[tuple]:
        return [
            ("stakeauthorize", "stakeauthorize"),
        ]

    def get_accounts_template(self) -> list[tuple[str, int]]:
        return [
            ("stake_account", ADDRESS_RW),
            ("clock_sysvar", ADDRESS_READ_ONLY),
            ("stake_or_withdraw_authority", ADDRESS_SIG_READ_ONLY),
            ("new_stake_or_withdraw_authority", ADDRESS_SIG_READ_ONLY),
            ("lockup_authority", ADDRESS_SIG_READ_ONLY, True),
        ]

    def validate(self, signer_pub_key: bytes) -> None:
        if self.funding_account != signer_pub_key:
            raise ProcessError("Invalid funding account")

    def show(self) -> Awaitable[None]:
        props = [
            ("Stakeauthorize", str(self.stakeauthorize)),
            ("Stake account", base58.encode(self.stake_account)),
            ("Clock sysvar", base58.encode(self.clock_sysvar)),
            ("Stake or withdraw authority", base58.encode(self.stake_or_withdraw_authority)),
            ("New stake or withdraw authority", base58.encode(self.new_stake_or_withdraw_authority)),
        ]
        if self.lockup_authority is not None:
            props.append(("Lockup authority", base58.encode(self.lockup_authority)))    

        return confirm_properties("authorize_checked", "Authorize Checked", props)

class AuthorizeCheckedWithSeedInstruction(Instruction):
    PROGRAM_ID = STAKE_PROGRAM_ID
    INSTRUCTION_ID = INS_AUTHORIZE_CHECKED_WITH_SEED

    stake_authorize: int
    authority_seed: str
    authority_owner: bytes

    stake_account: bytes 
    stake_or_withdraw_authority: bytes 
    clock_sysvar: bytes 
    new_stake_or_withdraw_authority: bytes 
    lockup_authority: bytes | None


    def get_data_template(self) -> list[tuple]:
        return [
            ("stake_authorize", "stakeauthorize"),
            ("authority_seed", "string"),
            ("authority_owner", "pubkey"),
        ]

    def get_accounts_template(self) -> list[tuple[str, int]]:
        return [
            ("stake_account", ADDRESS_RW),
            ("stake_or_withdraw_authority", ADDRESS_SIG_READ_ONLY),
            ("clock_sysvar", ADDRESS_READ_ONLY),
            ("new_stake_or_withdraw_authority", ADDRESS_SIG_READ_ONLY),
            ("lockup_authority", ADDRESS_SIG_READ_ONLY, True),
        ]

    def validate(self, signer_pub_key: bytes) -> None:
        if self.funding_account != signer_pub_key:
            raise ProcessError("Invalid funding account")

    def show(self) -> Awaitable[None]:
        props = [
            ("Stake_authorize", str(self.stake_authorize)),
            ("Authority_seed", str(self.authority_seed)),
            ("Authority_owner", base58.encode(self.authority_owner)),
            ("Stake account", base58.encode(self.stake_account)),
            ("Stake or withdraw authority", base58.encode(self.stake_or_withdraw_authority)),
            ("Clock sysvar", base58.encode(self.clock_sysvar)),
            ("New stake or withdraw authority", base58.encode(self.new_stake_or_withdraw_authority)),
        ]
        if self.lockup_authority is not None:
            props.append(("Lockup authority", base58.encode(self.lockup_authority)))    

        return confirm_properties("authorize_checked_with_seed", "Authorize Checked With Seed", props)

class SetLockupCheckedInstruction(Instruction):
    PROGRAM_ID = STAKE_PROGRAM_ID
    INSTRUCTION_ID = INS_SET_LOCKUP_CHECKED

    unix_timestamp: int
    epoch: int

    stake_account: bytes 
    lockup_authority_or_withdraw_authority: bytes 
    new_lockup_authority: bytes | None


    def get_data_template(self) -> list[tuple]:
        return [
            ("unix_timestamp", "i64"),
            ("epoch", "u64"),
        ]

    def get_accounts_template(self) -> list[tuple[str, int]]:
        return [
            ("stake_account", ADDRESS_RW),
            ("lockup_authority_or_withdraw_authority", ADDRESS_SIG_READ_ONLY),
            ("new_lockup_authority", ADDRESS_SIG_READ_ONLY, True),
        ]

    def validate(self, signer_pub_key: bytes) -> None:
        if self.funding_account != signer_pub_key:
            raise ProcessError("Invalid funding account")

    def show(self) -> Awaitable[None]:
        props = [
            ("Unix_timestamp", str(self.unix_timestamp)),
            ("Epoch", str(self.epoch)),
            ("Stake account", base58.encode(self.stake_account)),
            ("Lockup authority or withdraw authority", base58.encode(self.lockup_authority_or_withdraw_authority)),
        ]
        if self.new_lockup_authority is not None:
            props.append(("New lockup authority", base58.encode(self.new_lockup_authority)))    

        return confirm_properties("set_lockup_checked", "Set Lockup Checked", props)

