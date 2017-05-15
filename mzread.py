import struct
import capstone
import os
from collections import namedtuple, defaultdict

MZHEADER = '<2s13H'
tMZHEADER = namedtuple('MZHEADER', 'ID sz_last nb_pages nb_reloc sz_header '
    'sz_udata sz_exe SS SP checksum IP CS of_reloc nb_overlay')

path = os.path.expanduser('~/Games/dosbox/coloniz2/')

with open(path + 'opening.exe', 'rb') as f:
    hdr = f.read(28)
    st = tMZHEADER(*struct.unpack(MZHEADER, hdr))
    start = 0x527C #st.CS*16+st.IP
    f.seek(0)
    data = f.read()

print(st)

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
md.details = True

todo = [start]
targets = set(todo)
calls = defaultdict(set)
calls[start].add('start')
seen = set()
def explore(start):
    for i in md.disasm(data[start:], start):
        #print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        if i.address in seen:
            return
        seen.add(i.address)

        if i.mnemonic[0] == 'j' or i.mnemonic in ('call', 'lcall'):
            #import pdb; pdb.set_trace()
            tgt = None
            try:
                tgt = int(i.op_str, 0)
            except ValueError:
                try:
                    segment, offset = i.op_str.split(':')
                    segment = int(segment,0)
                    offset = int(offset,0)
                    tgt = 16*segment+offset
                except ValueError:
                    print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
            if tgt is not None:
                todo.append(tgt)
                if i.mnemonic in ('call', 'lcall'):
                    calls[tgt].add("called from 0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
                else:
                    targets.add(tgt)


while todo:
    explore(todo.pop())

call_addrs = sorted(calls) + [0xffffffff]
for j in range(len(call_addrs)-1):
    print('#function 0x%x' % call_addrs[j])
    print('\n'.join(calls[call_addrs[j]]))
    for i in md.disasm(data[call_addrs[j]:], call_addrs[j]):
        if i.address >= call_addrs[j+1]:
            break
        marker = '* ' if i.address in targets else '  '
        print("%s0x%x:\t%s\t%s" %(marker, i.address, i.mnemonic, i.op_str))
        if i.mnemonic[:3] in ('jmp', 'ret'):
            print()
            #break
    print()
