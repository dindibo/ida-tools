from dis import Instruction
from lib2to3.pgen2 import token
from pprint import pprint
import idc
import ida_dbg
import idautils
import ida_segment
import json
import hashlib
import random
import time

SEGMENT_MAX_VALUE = 0xffffffffffffffff

def perm_to_txt(perm):
    assert 0 <= perm <= 0b111 

    return ('r' if perm & segment.PERM_READ else '-') + ('w' if perm & segment.PERM_WRITE else '-') + \
            ('x' if perm & segment.PERM_EXECUTE else '-')

            
def txt_to_perm(txt):
    acc = 0

    if txt[0] == 'r':
        acc += 1
        
    if txt[1] == 'w':
        acc += 2
        
    if txt[2] == 'x':
        acc += 4

    return acc


class segment:
    PERM_EXECUTE    = 0b1
    PERM_WRITE      = 0b10
    PERM_READ       = 0b100

    def __init__(self, startEA, endEA, permission=0):
        self.startEA = startEA
        self.endEA = endEA
        self.permission = permission
        self.name=''

    def size(self):
        return self.endEA - self.startEA

    def permissionText(self):
        return perm_to_txt(self.permission)


    def __str__(self) -> str:
        return f'{hex(self.startEA)}\t-->\t{hex(self.endEA)}\t[{self.permissionText()}]'

# A generator function that iterates on each segment and returns its start EA
def iter_segment():
    t = idc.get_next_seg(0x0)

    while t != SEGMENT_MAX_VALUE:
        yield t
        t = idc.get_next_seg(t)


# A generator function that iterates on each segment and returns its start EA
def iter_segment_t():
    segs = [x for x in iter_segment()]
    return [ida_segment.getseg(x) for x in segs]


# ida_segment.getseg
# Runs an analysis on all segments and returns a list of each one
def map_segments():
    segs_EAs = iter_segment()
    segs = []
    last_segment = None
    temp_segment = None

    for ea in segs_EAs:
        temp_seg_t = ida_segment.getseg(ea)
        temp_segment = segment(ea, -1, permission=temp_seg_t.perm)

        # Use < and > not <= =>
        # Do last
        if last_segment is not None:
            last_segment.endEA = temp_segment.startEA

        # Finish temp
        segs.append(temp_segment)

        # Update last
        last_segment = temp_segment

    # Do last
    last_segment.endEA = SEGMENT_MAX_VALUE

    return segs

# Gets value of RIP
get_ip = lambda : idc.get_reg_value('rip')


# Search binary data downwards
def search_down_bin(ea, code_hex):
    res = idc.find_binary(ea, idc.SEARCH_DOWN, code_hex)
    return res


# Checks if disassembly of EA yields expected code
def check_if_code(ea, codeSubString):
    return codeSubString.lower() in (idc.generate_disasm_line(ea, 0)).lower()


def is_ea_in_segs(ea, segs):
    for seg in segs:
        if seg.startEA < ea < seg.endEA:
            return True

    return False


def get_char_at_ea(ea):
    return idc.get_bytes(ea, 1)


def get_string_from_ea(ea):
    temp = b''
    ptr = ea

    ch = get_char_at_ea(ptr)

    while ch != b'\x00':
        temp += ch
        ptr += 1
        ch = get_char_at_ea(ptr)

    return temp


def get_ea_of_prev_line(ea):
    prev_dis = idc.generate_disasm_line(ea-1, flags=0 )
    opcode_len = len(Assemble(ea, prev_dis)[1])

    return ea - opcode_len


def add_bpt_python(ea, code, group=''):
    bpt = ida_dbg.bpt_t()
    bpt.set_abs_bpt(ea)
    bpt.type=4
    bpt.flags=268435464
    bpt.condition=code
    bpt.elang="Python"

    if group != '':
        ida_dbg.set_bpt_group(bpt, group)

    idc.add_bpt(bpt)


def current_milli_time():
    return round(time.time() * 1000)


def md5(txt):
    result = hashlib.md5(txt.encode())
    return result.hexdigest()


def gen_nonce():
    timestamp = random.random()
    return md5(str(current_milli_time()) +  str(timestamp))


def add_uuidToken_to_code(pythonCode):
    tok = gen_nonce()


    temp = pythonCode
    temp += '\r\n'
    temp += '#' + tok

    return temp, tok


def write_UUIDToken(token):
    global ARG_BPT_CODE_FNAME

    fname = ARG_BPT_CODE_FNAME
    fname = fname.split('\\')
    fname.pop()
    fname = '\\'.join(fname)
    fname += '\\'

    fname += 'code-break.token'

    with open(fname, 'w+') as f:
        f.write(token)

    return fname


### Execution

# Parameters

ARG_OPCODE          = 'rep stosb'
ARG_HEX_OPCODE      = 'F3 AA'
ARG_BPT_CODE_FNAME  = 'C:\\Temp\\code-break\\bpt-code.py'

opcode_len = ARG_HEX_OPCODE.count(' ') + 1
segs = map_segments()
exec_segs = [seg for seg in segs if seg.permission & segment.PERM_EXECUTE]

instructions = []

for x in exec_segs:
    start = x.startEA

    inst_offset = search_down_bin(start, ARG_HEX_OPCODE)

    while True:
        # Check if in current segment or move to next segment
        if not(x.startEA < inst_offset < x.endEA):
            break
        
        # Check if expected opcode and add to instructions
        if check_if_code(inst_offset, ARG_OPCODE):
            instructions.append(inst_offset)
        
        inst_offset = search_down_bin(inst_offset + opcode_len, ARG_HEX_OPCODE)

desired_condition = ''

with open(ARG_BPT_CODE_FNAME, 'r') as f:
    desired_condition = f.read()

newCode, uuidToken = add_uuidToken_to_code(desired_condition)
desired_condition = newCode

write_UUIDToken(uuidToken)

for x in instructions:
    add_bpt_python(get_ea_of_prev_line(x), desired_condition, group='code-break')
