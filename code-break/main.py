from pprint import pprint
import idc
import ida_segment
import json

SEGMENT_MAX_VALUE = 0xffffffffffffffff

def perm_to_txt(perm):
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

    for x in segs_EAs:
        segs.append(segment())

# Gets value of RIP
get_ip = lambda : idc.get_reg_value('rip')


# Search binary data downwards
def search_down_bin(code):
    res = idc.find_binary(get_ip(), idc.SEARCH_DOWN, code)
    return res

# Checks if disassembly of EA yields expected code
def check_if_code(ea, codeSubString):
    return codeSubString.lower() in (idc.generate_disasm_line(ea, 0)).lower()


segs = [x for x in iter_segment()]
segs = [ida_segment.getseg(x) for x in segs]

print(segs[0].perm)


for x in 