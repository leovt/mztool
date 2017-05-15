import struct
import capstone
import os
import sys
import json
from collections import namedtuple, defaultdict
from cmd import Cmd
import binascii

MZHEADER = '<2s13H'
tMZHEADER = namedtuple('MZHEADER', 'ID sz_last nb_pages nb_reloc sz_header '
    'sz_udata sz_exe SS SP checksum IP CS of_reloc nb_overlay')

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
md.details = True

class Command(Cmd):
    prompt = '(mzdisasm) '

    def do_save(self, arg):
        self.info.save()

    def do_header(self, arg):
        print(self.info.header)

    def do_quit(self, arg):
        self.info.save()
        return True

    def do_goto(self, arg):
        adr = int(arg, 0)
        self.current = adr
        self.disasm = iter(md.disasm(self.info.data[adr:], adr))
        for i, instr in enumerate(self.disasm):
            for lbl in self.info.labels.get(instr.address, []):
                print('%s:' % lbl)
            print("%s 0x%x: %-10s  %-6s  %s" % ('->' if instr.address == self.current else '  ',
                                             instr.address,
                                             binascii.hexlify(instr.bytes).decode('ascii'),
                                             instr.mnemonic,
                                             instr.op_str))
            if i>5:
                break

    def do_label(self, arg):
        arg = arg.split()
        if len(arg) == 1:
            adr = self.current
        else:
            adr = int(arg[1], 0)
        self.info.labels.setdefault(adr, [])
        self.info.labels[adr].append(arg[0])

class ExeInfo:
    def __init__(self, fname):
        self.fname = fname
        with open(fname, 'rb') as f:
            hdr = f.read(28)
            self.header = tMZHEADER(*struct.unpack(MZHEADER, hdr))
            f.seek(0)
            self.data = f.read()
            self.labels = {}
        if os.path.exists(fname+'.json'):
            with open(fname+'.json', 'r') as f:
                j = json.load(f)
                self.labels = {int(k):v for k,v in j['labels'].items()}

    def save(self):
        with open(self.fname+'.json', 'w') as f:
            j = json.dump({'labels':self.labels}, f)

if __name__ == '__main__':
    cmd = Command()
    cmd.info = ExeInfo(sys.argv[1])
    cmd.current = 0
    cmd.cmdloop()

path = os.path.expanduser('~/Games/dosbox/coloniz2/')
