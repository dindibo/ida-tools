import idc

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

print('[CODE-BREAK]')
print(get_string_from_ea(idc.get_reg_value('rdi')))
