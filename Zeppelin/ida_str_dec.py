import idautils
import idaapi
import zep_dec


DECRYPT_STR_FUNC_EA = 0x4101F0

DECRYPT_STR_FUNC_NAME = 'decrypt_str'
DECRYPT_STR_FUNC_TYPE = \
    'void __usercall decrypt_str(void *enc_data@<eax>, void *dest@<edx>)'


def get_arg_data(arg_ea):

    inst = DecodeInstruction(arg_ea)
    if (inst.itype != idaapi.NN_mov) or (inst.ops[1].type != o_imm):
        return None

    str_ea = inst.ops[1].value
    str_len = ida_bytes.get_dword(str_ea - 4)
    return ida_bytes.get_bytes(str_ea, str_len)


def decrypt_str(call_ea):

    arg_addrs = idaapi.get_arg_addrs(call_ea)
    if arg_addrs is None:
        return None

    enc_data = get_arg_data(arg_addrs[0])
    if enc_data is None:
        return None

    dec_data = zep_dec.decrypt_data(enc_data)

    return dec_data.decode()


#
# Main
#

ida_name.set_name(DECRYPT_STR_FUNC_EA, DECRYPT_STR_FUNC_NAME)

if SetType(DECRYPT_STR_FUNC_EA, DECRYPT_STR_FUNC_TYPE) == 0:
    raise Exception('Failed to set type of ' + DECRYPT_STR_FUNC_NAME + '.')

auto_wait()

enc_str_count = 0
dec_str_count = 0

for xref in CodeRefsTo(DECRYPT_STR_FUNC_EA, 1):

    enc_str_count += 1

    dec_str = decrypt_str(xref)

    if (dec_str is None):
        print('%08X: Failed to decrypt string.' % xref)
        continue

    s = dec_str.encode('unicode_escape').decode().replace('\"', '\\"')
    set_cmt(xref, '\"' + s + '\"', 1)

    dec_str_count += 1

print(str(enc_str_count) + ' string(s) found.')
print(str(dec_str_count) + ' string(s) decrypted.')
