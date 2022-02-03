import idc
import ida_dbg


def add_bpt_python(ea, code='', group=''):
    bpt = ida_dbg.bpt_t()
    bpt.set_abs_bpt(ea)

    if code != '':
        bpt.type=4
        bpt.flags=268435464
        bpt.elang="Python"
        bpt.condition=code


    if group != '':
        ida_dbg.set_bpt_group(bpt, group)

    idc.add_bpt(bpt)

### Execution

# Parameters

ARG_BPT_FNAME   = 'C:\\Temp\\auto-breakpoint\\bpt.txt'
ARG_BPT_CODE    = 'C:\\Temp\\auto-breakpoint\\code.py'


desired_condition = ''
bpt_eas = []

if ARG_BPT_CODE != '':
    with open(ARG_BPT_CODE, 'r') as f:
        desired_condition = f.read()

with open(ARG_BPT_FNAME, 'r') as f:
        bpts_dat = f.read()

# Warning: Eval used
bpt_eas = [eval(x) for x in bpts_dat.split()]

for ea in bpt_eas:
    add_bpt_python(ea, code=desired_condition)
