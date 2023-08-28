# generated from program.py.mako
# do not edit manually!
## getProgramId(program) <<-- generates program id text
<%def name="getProgramId(program)">${"_".join(program["name"].upper().split(" ") + ["ID"])}</%def>\
## getInstructionIdText(instruction) <<-- generates instruction ID text
<%def name="getInstructionIdText(instruction)">${"_".join(["INS"] + instruction["name"].upper().split(" "))}</%def>\
## getInstructionUiIdentifier(instruction) <<-- generates UI identifier for show function
<%def name="getInstructionUiIdentifier(instruction)">${"_".join(instruction["name"].lower().split(" "))}</%def>\
## getHandleFunction(program) <<-- generates instruction handle function name
<%def name="getHandleFunction(program)">handle_${"_".join(program["name"].lower().split(" "))}_instruction</%def>\
## getClassName(instruction) <<-- generates class name from instruction name
<%def name="getClassName(instruction)">${instruction["name"].replace(" ", "")}Instruction</%def>\
## getReferenceName(reference) <<-- formatting reference account name
<%def name="getReferenceName(reference)">${"_".join(reference["name"].lower().split(" "))}</%def>\
## getReferenceOptionalType(reference) <<-- generates (| None) if the reference account is optional 
<%def name="getReferenceOptionalType(reference)">\
% if reference["optional"]:
| None
% endif
</%def>\
## getReferenceTypeTemplate(reference) <<-- generates reference account type based on access and signer properties
<%def name="getReferenceTypeTemplate(reference)">\
% if reference["signer"]:
    % if reference["access"] == "w":
ADDRESS_SIG\
    % else:
ADDRESS_SIG_READ_ONLY\
    % endif
% else:
    % if reference["access"] == "w":
ADDRESS_RW\
    % else:
ADDRESS_READ_ONLY\
    % endif
% endif
</%def>\
## getReferenceOptionalTemplate(reference) <<-- if a reference account is optional shall return (, True)
<%def name="getReferenceOptionalTemplate(reference)">\
% if reference["optional"]:
, True\
% endif
</%def>\

from typing import TYPE_CHECKING

from trezor.crypto import base58
from trezor.enums import ButtonRequestType
from trezor.strings import format_amount
from trezor.ui.layouts import confirm_output, confirm_properties
from trezor.wire import ProcessError

from ..constants import ADDRESS_RW, ADDRESS_SIG, ADDRESS_SIG_READ_ONLY
from . import ${getProgramId(program)}, Instruction

if TYPE_CHECKING:
    from typing import Awaitable

    from ..types import RawInstruction

## generates instruction identifiers with values
% for instruction in program["instructions"]:
${getInstructionIdText(instruction)} = ${instruction["id"]}
% endfor

def ${getHandleFunction(program)}(
    raw_instruction: RawInstruction, signer_pub_key: bytes
) -> Awaitable[None]:
    program_id, _, _ = raw_instruction
    assert base58.encode(program_id) == ${getProgramId(program)}

    instruction = _get_instruction(raw_instruction)

    instruction.parse()
    instruction.validate(signer_pub_key)
    return instruction.show()


def _get_instruction(raw_instruction: RawInstruction) -> Instruction:
    _, _, data = raw_instruction

    assert data.remaining_count() >= 4
    instruction_id = int.from_bytes(data.read(4), "little")
    data.seek(0)

## generates if - elif- else statement to handle instructions
% for instruction in program["instructions"]:
    % if instruction == program["instructions"][0]:
    if ${getInstructionIdText(instruction)} == instruction_id:
        return ${getClassName(instruction)}(raw_instruction)
    % else:
    elif ${getInstructionIdText(instruction)} == instruction_id:
        return ${getClassName(instruction)}(raw_instruction)
    % endif
% endfor
    else:
        # TODO SOL: blind signing
        raise ProcessError("Unknown system program instruction")

## generates classes for instructions
% for instruction in program["instructions"]:
class ${getClassName(instruction)}(Instruction):
    PROGRAM_ID = ${getProgramId(program)}
    INSTRUCTION_ID = ${getInstructionIdText(instruction)}

    ## generates properties for instruction parameters
    % for parameter in instruction["parameters"]:
    ${parameter["name"]}: ${parameter["ptype"]}
    % endfor

    ## generates properties for reference accounts
    % for reference in instruction["references"]:
    ${getReferenceName(reference)}: bytes ${getReferenceOptionalType(reference)}
    % endfor

    def get_data_template(self) -> list[tuple]:
        return [
    ## generates data template for parser
    % for parameter in instruction["parameters"]:
            ("${parameter["name"]}", "${parameter["type"].lower()}"),
    % endfor
        ]

    def get_accounts_template(self) -> list[tuple[str, int]]:
        return [
    ## generates account template for parser
    % for reference in instruction["references"]:
            ("${getReferenceName(reference)}", ${getReferenceTypeTemplate(reference)}${getReferenceOptionalTemplate(reference)}),
    % endfor
        ]

    def validate(self, signer_pub_key: bytes) -> None:
        if self.funding_account != signer_pub_key:
            raise ProcessError("Invalid funding account")

    def show(self) -> Awaitable[None]:
        props = [
    ## generates property list from parameters
    % for parameter in instruction["parameters"]:
        % if parameter["ptype"] == "bytes":
            ("${parameter["name"].capitalize()}", base58.encode(self.${parameter["name"]})),
        % else:
            ("${parameter["name"].capitalize()}", str(self.${parameter["name"]})),
        % endif
    % endfor
    ## generates property list from non-optional reference accounts
    % for reference in instruction["references"]:
        % if not reference["optional"]:
            ("${reference["name"].capitalize()}", base58.encode(self.${getReferenceName(reference)})),
        % endif
    % endfor
        ]
    ## generates property list from optional reference accounts
    % for reference in instruction["references"]:
        % if reference["optional"]:
        if self.${getReferenceName(reference)} is not None:
            props.append(("${reference["name"].capitalize()}", base58.encode(self.${getReferenceName(reference)})))    
        % endif
    % endfor

        ## returns UI object
        return confirm_properties("${getInstructionUiIdentifier(instruction)}", "${instruction["name"]}", props)

% endfor
