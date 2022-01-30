import idc
import ida_dbg


def gen_token_path():
    global ARG_FOLDER
    return ARG_FOLDER + '\\code-break.token'


def read_token():
    with open(gen_token_path(), 'r') as f:
        return f.read()


def bpt_t_from_index(bpt_i):
    ea = idc.get_bpt_ea(bpt_i)
    temp = ida_dbg.bpt_t()

    ida_dbg.get_bpt(ea, temp)

    return temp


def is_bpt_relevant(bpt_t, token):
    return token in bpt_t.condition


### Execution

# Parameters

ARG_FOLDER    = 'C:\\Temp\\code-break'


uuidToken = read_token()

# FIXME:    For some reason sometimes it fails,
#           running  it  several  times  solves
#           the problem
for x in range(10):
    for bpt_i in range(ida_dbg.get_bpt_qty()):
        bpt_t_temp = bpt_t_from_index(bpt_i)

        if is_bpt_relevant(bpt_t_temp, uuidToken):
            ida_dbg.del_bpt(bpt_t_temp.ea)

