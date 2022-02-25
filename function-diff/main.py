from ast import arg
from hmac import digest
import re
import hashlib
from sys import argv, exit


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
    return list(mydict.keys())[list(mydict.values()).index(val)]


def diff_progs(sig_prog1, sig_prog2, op='^'):
    hashes = [list(sig_prog1.values()), list(sig_prog2.values())]

    a = set(hashes[0])
    b = set(hashes[1])

    if op == '^':
        diff = a ^ b
    elif op == '&':
        diff = a & b

    funcs = None

    if op  == '^':
        funcs = [[],[]]

        for hash in diff:
            if hash in a:
                funcs[0].append(key_by_value(sig_prog1, hash))
            else:
                funcs[1].append(key_by_value(sig_prog2, hash))

        funcs[0].sort()
        funcs[1].sort()
    elif op == '&':
        funcs = []

        for hash in diff:
            funcs.append(key_by_value(sig_prog1, hash))

    return funcs


def convert_func_name_to_func_code(func_txts):
    func_code = dict()

    for func_name in func_txts.keys():
        func_code[func_name] = extract_func_opcodes(func_txts[func_name])
        func_code[func_name] = '' if func_code[func_name] == '' else gen_md5(func_code[func_name])

    return func_code


if len(argv) != 3:
    print('Usage: {0} <Asm1> <Asm2>'.format(argv[0]))
    exit(1)    

fname1, fname2 = argv[1], argv[2]
func_code_arr = []

with open(fname1, 'r', encoding="mbcs") as f:
    dat = f.read()
    func_txts = extract_all_funcs(dat)
    func_code = convert_func_name_to_func_code(func_txts)
    func_code_arr.append(func_code)

with open(fname2, 'r', encoding="mbcs") as f:
    dat = f.read()
    func_txts = extract_all_funcs(dat)
    func_code = convert_func_name_to_func_code(func_txts)
    func_code_arr.append(func_code)

diffs = diff_progs(func_code_arr[0], func_code_arr[1])
sames = diff_progs(func_code_arr[0], func_code_arr[1], op='&')

print('Different functions in {0}:'.format(fname1))
for x in diffs[0]:
    print(x)

print('\n'*3)

print('Different functions in {0}:'.format(fname2))

for x in diffs[1]:
    print(x)

print('\n'*6)

print('Same functions both:')

for x in sames:
    print(x)