# generated from __init__.py.mako
# do not edit manually!
## getProgramId(program) <<-- generates program id text
<%def name="getProgramId(program)">${"_".join(program["name"].upper().split(" ") + ["ID"])}</%def>\
## getHandleFunction(program) <<-- generates instruction handle function name
<%def name="getHandleFunction(program)">handle_${"_".join(program["name"].lower().split(" "))}_instruction</%def>\
## getFileName(program) <<-- generates the filename for each program
<%def name="getFileName(program)">${"_".join(program["name"].lower().split(" "))}</%def>\
from typing import TYPE_CHECKING
import base58

if TYPE_CHECKING:
    from ..types import Address, Data, RawInstruction

## creates the program identifier with address from the template
% for program in programs["programs"]:
${getProgramId(program)} = "${program["id"]}"
% endfor


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

## imports each program
% for program in programs["programs"]:
    from .${getFileName(program)} import ${getHandleFunction(program)}
% endfor

    for instruction in instructions:
        program_id, _, _ = instruction

        encoded_program_id = base58.encode(program_id)

## calls the programs to handle corresponding instructions
% for program in programs["programs"]:
    % if program == programs["programs"][0]:
        if ${getProgramId(program)} == encoded_program_id:
            await ${getHandleFunction(program)}(instruction, signer_pub_key)
    % else:
        elif ${getProgramId(program)} == encoded_program_id:
            await ${getHandleFunction(program)}(instruction, signer_pub_key)
    % endif
% endfor
        else:
            # TODO SOL: blind signing for unknown programs
            raise ProcessError(f"Unknown program id: {encoded_program_id}")
