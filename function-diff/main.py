import re
import hashlib

hex_dec = '0123456789ABCDEF'
proc_token = ' S U B R O U T I N E '

def gen_md5(txt):
    return hashlib.md5(txt.encode('utf-8')).hexdigest()

def extract_all_funcs(src):
    has_proc_encountered = False
    funcs = dict()

    last_func_name = ''

    for i, line in enumerate(src.split('\n')):

        # if token of function
        if proc_token in line:
            has_proc_encountered = True

        # if start of function after token
        elif 'proc near' in line and has_proc_encountered:
            line_words = line.split()
            proc_ind = line_words.index('proc')

            if proc_ind <= 0:
                has_proc_encountered = False
                continue

            func_name = line_words[proc_ind - 1]
            funcs[(func_name)] = ''
            has_proc_encountered = False
            last_func_name = func_name

        # if during function content
        else:
            if last_func_name != '':
                funcs[last_func_name] += line + '\n'
            

    return funcs
            
def extract_func_opcodes__core(func_content):
    is_code = lambda code: len(code) > 2

    pat = re.compile(r'\.text:[0-9A-F]+ (([0-9A-F]{2} )*)')
    all_code =''

    for line in func_content.split('\n'):
        srch = pat.search(line)

        if srch:
            code = srch.group(1)

            if is_code(code):
                all_code += code

    return all_code            


def extract_func_opcodes(func_content):
    global hex_dec

    opcodes = extract_func_opcodes__core(func_content)
    res = ''.join(opcodes.split(' '))

    #if len(res) % 2 != 0 or not res.upper() == res or not all(ch in res in hex_dec for ch in res):
    #    return ''

    return res


def signify_funcs(func_opcodes):
    for key in func_opcodes.keys():
        tmp = func_opcodes[key]
        func_opcodes[key] = gen_md5(tmp)


def key_by_value(mydict, val):
    return mydict.keys()[mydict.values().index(val)]


def diff_progs(sig_prog1, sig_prog2):
    hashes = [list(sig_prog1.values()), list(sig_prog2.values())]

    a = set(hashes[0])
    b = set(hashes[1])

    diff = a ^ b

    funcs = [[],[]]

    for hash in diff:
        if hash in a:
            funcs[0].append(key_by_value(a, hash))
        else:
            funcs[1].append(key_by_value(b, hash))

    return funcs


with open('data.txt', 'r', encoding="mbcs") as f:
    dat = f.read()


func_txts = extract_all_funcs(dat)
func_code = dict()

for func_name in func_txts.keys():
    func_code[func_name] = extract_func_opcodes(func_txts[func_name])

print(func_code['_main'])
