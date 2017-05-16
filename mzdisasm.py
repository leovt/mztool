import struct
import capstone
import os
import sys
import json
import cmd
from collections import namedtuple, defaultdict
import binascii

MZHEADER = '<2s13H'
tMZHEADER = namedtuple('MZHEADER', 'ID sz_last nb_pages nb_reloc sz_header '
    'sz_udata sz_exe SS SP checksum IP CS of_reloc nb_overlay')

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
md.details = True

class Command(cmd.Cmd):
    prompt = '(mzdisasm) '

    def __init__(self, state):
        cmd.Cmd.__init__(self)
        self.state = state

    def do_save(self, arg):
        self.state.save()

    def do_header(self, arg):
        print(self.state.header)

    def do_quit(self, arg):
        '''quit
           save the session and quit the application'''
        self.state.save()
        return True

    def do_goto(self, arg):
        '''goto [address]
           set the current address to [address]'''
        try:
            address = int(arg, 0)
        except ValueError:
            print('Illegal argument %r' % arg)
            return
        self.state.goto(address)
        print(self.state.show())

    def do_find(self, arg):
        try:
            arg = binascii.unhexlify(arg)
        except:
            print('Illegal argument %r' % arg)
            return
        self.state.find(arg)
        print(self.state.show())

    def do_show(self, arg):
        '''show [!]lines
           display the given number of lines of data.
           by default the next lines are shown.
           if the form with ! is used, the lines are
           shown starting from the current position.'''
        if arg[0] == '!':
            self.state.reset_shown()
            arg = arg[1:]
        try:
            lines = int(arg, 0)
        except ValueError:
            print('Illegal argument %r' % arg)
            return
        for i in range(lines):
            line = self.state.show()
            print(line)
            if line == 'EOF':
                break

    def do_mode(self, arg):
        arg = arg.lower()
        if arg not in ('hex', 'bin', 'asm'):
            print('Illegal argument %r' % arg)
            return
        self.state.set_displaymode(arg)

    def emptyline(self):
        print(self.state.show())

    def do_label(self, arg):
        arg = arg.split()
        if len(arg) == 1:
            adr = self.current
        else:
            adr = int(arg[1], 0)
        self.state.labels.setdefault(adr, [])
        self.state.labels[adr].append(arg[0])


class State(object):
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
        self.address = 0
        self.mode = 'hex'
        self.reset_shown()

    def show(self):
        return next(self.lines, 'EOF')

    def goto(self, address):
        self.address = address
        self.reset_shown()

    def set_displaymode(self, mode):
        self.mode = mode
        self.reset_shown()

    def reset_shown(self):
        if self.mode == 'hex':
            self.lines = (
                '%2s 0x%06X: %s  %s  %s' % (
                    '->' if self.address == a else '', a,
                    ' '.join('%02X' % c for c in self.data[a:a+8]),
                    ' '.join('%02X' % c for c in self.data[a+8:a+16]),
                    ''.join((chr(c) if 32 <= c < 127 else '.') for c in self.data[a:a+16]))
                for a in range(self.address, len(self.data), 16))
        elif self.mode == 'bin':
            self.lines = (
                '%2s 0x%06X:  %s  (0x%02X)  %s' % (
                    '->' if self.address == a else '', a,
                    bin(c)[2:].rjust(8,'0'), c, (chr(c) if 32 <= c < 127 else ''))
                for (a,c) in enumerate(self.data[self.address:], self.address))
        elif self.mode == 'asm':
            def lines():
                for instr in md.disasm(self.data[self.address:], self.address):
                    for lbl in self.labels.get(instr.address, []):
                        yield '%s:' % lbl
                    yield ("%s 0x%x: %-10s  %-6s  %s" % (
                            '->' if instr.address == self.address else '  ',
                            instr.address,
                            binascii.hexlify(instr.bytes).decode('ascii'),
                            instr.mnemonic, instr.op_str))
            self.lines = iter(lines())

    def find(self, arg):
        def lines():
            pos = -1
            while True:
                pos = self.data.find(arg, pos+1)
                if pos < 0:
                    return
                yield '   0x%06X: %s' % (pos, ' '.join('%02X' % c for c in self.data[pos:pos+8]))
        self.lines = iter(lines())


    def save(self):
        with open(self.fname+'.json', 'w') as f:
            j = json.dump({'labels':self.labels}, f)


if __name__ == '__main__':
    cmd = Command(State(sys.argv[1]))
    cmd.cmdloop()
