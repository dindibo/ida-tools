from pprint import pprint
import idc
import ida_segment
import json

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
def search_down_bin(code):
    res = idc.find_binary(get_ip(), idc.SEARCH_DOWN, code)
    return res

# Checks if disassembly of EA yields expected code
def check_if_code(ea, codeSubString):
    return codeSubString.lower() in (idc.generate_disasm_line(ea, 0)).lower()

segs = map_segments()
exec_segs = [seg for seg in segs if seg.permission & segment.PERM_EXECUTE]

for x in exec_segs:
    print(x)
