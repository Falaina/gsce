# -*- coding: utf-8 -*-
# gsce - PersonA ～オペラ座の怪人～ Translation Tools
# Written in 2012 By Falaina falaina@falaina.net
# To the extent possible under law, the author(s) have dedicated all
# copyright and related and neighboring rights to this software to the
# public domain worldwide. This software is distributed without any
# warranty.  You should have received a copy of the CC0 Public Domain
# Dedication along with this software. If not, see
# <http://creativecommons.org/publicdomain/zero/1.0/>.
from __future__ import print_function, division, unicode_literals
import ichiko
import sys
from binascii import hexlify
from bitstring   import pack
from collections import namedtuple
from cStringIO   import StringIO
from ctypes import c_uint32
from pprint import pprint
from struct import unpack
import numpy as np
import optparse
from six.moves import reprlib

aRepr = reprlib.aRepr
repr = aRepr.repr
aRepr.maxother = 32
reload(ichiko)

VERIFY  = False
XOR_KEY = None

PackedStruct   = ichiko.PackedStruct
check_args     = ichiko.check_args
Invariant      = ichiko.Invariant
InvariantCheck = ichiko.InvariantCheck
logging        = ichiko.ichilog
getlogger      = logging.getlogger

logging.STDIO_HANDLER.setLevel(logging.DEBUG)
logger = getlogger('gsce')

def create_xor_key():
    global XOR_KEY
    if XOR_KEY:
        return
    XOR_KEY = np.zeros(256, np.uint32)
    seed    = 0x915354a9
    cur_int = seed
    for i in range(256):
        XOR_KEY[i] = cur_int
        cur_int = 0x41C64E6D * cur_int + 12345
        cur_int = c_uint32(cur_int).value


def verify_encrypt(cipher_block, plain_block, key_block=None, block_size=0x400):
    if not VERIFY:
        return
    logger.debug('Checking Invariant on encrypt_block')
    invariant = cipher_block == encrypt_block._fn(decrypt_block._fn(cipher_block, key_block, block_size),
                                              key_block, block_size)
    InvariantCheck(invariant, 'D(E(p_txt)) != p_txt')


def verify_decrypt(plain_block, cipher_block, key_block=None, block_size=0x400):
    if not VERIFY:
        return
    logger.debug('Checking Invariant on decrypt_block')
    invariant = plain_block  == decrypt_block._fn(encrypt_block._fn(plain_block, key_block, block_size),
                                              key_block, block_size)
    InvariantCheck(invariant, 'E(D(c_txt)) != c_txt')


@Invariant(post=verify_decrypt)
def decrypt_block(cipher_block, key_block=None, block_size=0x400):
    cipher_block = np.fromstring(cipher_block, np.uint8)
    if key_block is None:
        key_block = XOR_KEY
    key_block   = key_block.view(np.uint8)
    plain_block = np.zeros(block_size, np.uint8)
    assert len(cipher_block) == len(key_block), \
        'key block and cipher block should be same size'

    cipher_idx = 67

    plain_block[0] = cipher_block[44]
    for plain_idx in range(1, block_size):
        cur_char = plain_block[plain_idx - 1] ^ cipher_block[cipher_idx]
        cipher_idx   = (cipher_idx + 0x17) & 0x3FF

        plain_block[plain_idx] = cur_char
    return (plain_block ^ key_block).tostring()


@Invariant(post=verify_encrypt)
def encrypt_block(plain_block, key_block=None, block_size=0x400):
    plain_block = np.fromstring(plain_block, np.uint8)
    if key_block is None:
        key_block = XOR_KEY
    key_block = key_block.view(np.uint8)
    cipher_block = np.zeros(block_size, np.uint8)

    plain_block = plain_block ^ key_block
    init_idx = 44
    for _ in range(block_size):
        init_idx = (init_idx + 0x17) & 0x3FF

    cipher_idx = init_idx
    for plain_idx in range(block_size - 1, 0, -1):
        cur_char = plain_block[plain_idx] ^ plain_block[plain_idx - 1]
        cipher_idx = (cipher_idx - 0x17)  & 0x3FF

        cipher_block[cipher_idx] = cur_char
    cipher_block[44] = plain_block[0]
    return cipher_block.tostring()

# Guesses whether or something is a 'reasonable' size
def assertSize(n, h=2048, msg=''):
    if n >= 0 and n <= h:
        return
    raise ValueError('{} too large(max:{}): {}'.format( n, h, msg))

def assertEqual(a, b, msg=''):
    if a == b:
        return
    raise ValueError('{} - {} does not equal {}'.format(msg, a, b))

class EntryList(list):
    def getByIndex(self, idx):
        return [entry for entry in self if entry.index == idx][0]

# Represents information on objects that seem to have an associated
# String list, and VM(?) Instructions
class ContextInformation(PackedStruct):
    _fields_ = [                # The variable names are weird as I need them to match up with IDA notes
        ('dw58_00',       'uintle:  32',    0x00),
        ('dw40_04',       'uintle:  32',    0x04),
        ('dw44_08',       'uintle:  32',    0x08),
        ('dw50_0C',       'uintle:  32',    0x0C),
        ('dw28_10',       'uintle:  32',    0x10),
        ('dw10_14',       'uintle:  32',    0x14),
        ('dw20_18',       'uintle:  32',    0x18),
        ('unk1_1C',       'uintle:  32',    0x1C),
    ]


    def __init__(self):
        super(ContextInformation, self).__init__()

    def parse(self, s):
        super(ContextInformation, self).parse(s)
        self.info1  = unpack(str('<' + 'I'*self.dw44_08), 
                             s.read('bytes: {}'.format(self.dw44_08*4)))
        self.info2  = unpack(str('<' + 'Q'*self.dw50_0C), 
                             s.read('bytes: {}'.format(self.dw50_0C*8)))
        self.info3  = unpack(str('<' + 'I'*self.dw28_10), 
                             s.read('bytes: {}'.format(self.dw28_10*4)))
# There is an associated, but stored separately, table of objects (strings, etc.)
# the Context references
class ContextEntry(PackedStruct):
    _fields_ = [
        ('index',        'uintle: 16',   0x00), # The index for parent context
        ('subentry',     'uintle: 16',   0x02),
        ('num_chars',    'intle:  32',   0x04), # Number of chars in the string table
    ]

    def __init__(self):
        super(ContextEntry, self).__init__()
        
    def parse(self, s):
        size = 0
        super(ContextEntry, self).parse(s)
        if self.index < 0:
            return
        if self.num_chars > 0:
            self.rawstring = s.readstring(self.num_chars * 2, 'utf-16-le', 32000)
            size += self.num_chars * 2 + 8
        if self.subentry:
            subentry_size = s.read('uintle: 32')
            self.subentries = unpack(str('<' + 'Q' * subentry_size), 
                                     s.read('bytes: {}'.format(subentry_size * 8)))
            size += subentry_size * 8 + 8
        self.size = size

class GSCEFile(PackedStruct):
    _fields_ = [
        ('magic_no',     'bytes:   4',    0x000),
        ('dw_04',        'uintle: 32',    0x004),
        ('type0',        'uintle: 16',    0x008),
        ('type1',        'uintle: 16',    0x00A),
        ('cnt_elem',     'uintle: 32',    0x00C),
        ('cnt_10',       'uintle: 32',    0x010),
        ('unk_14',       'uintle: 32',    0x014),
        ('cnt_18',       'uintle: 32',    0x018),
        ('cnt_1c',       'uintle: 32',    0x01C),
        ('size_20',      'uintle: 32',    0x020),
        ('unk_24',       'bytes:  16',    0x024),
        ('cnt_menu',     'uintle: 32',    0x034),
        ('cnt_38',       'uintle: 32',    0x038),
        ('cnt_var',      'uintle: 32',    0x03C),
        ('unk_40',       'uintle: 32',    0x040),
        ('unk_44',       'uintle: 32',    0x044),
        ('unk_48',       'uintle: 32',    0x048),
        ('cnt_fn',       'uintle: 32',    0x04C),
        ('unk_50',       'bytes: 272',    0x050),
        ('cnt_k5',       'uintle: 32',    0x160)
    ]
    _pprint_fields = [x[0] for x in _fields_ if not x[0].startswith('unk_')]

    def __init__(self):
        super(GSCEFile, self).__init__()
        self.scenes = []

    def parse(self, s):
        super(GSCEFile, self).parse(s)
        print(self)
        assertEqual('GSCE', self.magic_no, 'Magic number invalid')
        s.bytepos = 0x200 + (894 * 0x220)
        logger.info('Parsing [{}] k5 files [{:x}]'.format(self.cnt_k5, s.bytepos))
        logger.debug(repr(s.readstrings(0x40, self.cnt_k5, 'utf-16-le')))

        ustr1 = s.read('bytes: 512').decode('utf-16-le')
        print(ustr1)
            
        def parse_mixed_section(name, size_str, num_ints, cnt, encoding='utf-16-le'):
            logger.info('Parsing [{}] {} [{:x}]'.format(cnt, name, s.bytepos))
            items = []
            for _ in range(cnt):
                items.append((s.readstring(size_str, encoding), s.readlist(['uintle: 32'] * num_ints)))
            logger.debug(repr(items))
            return items

        def parse_string_section(name, size, cnt, encoding='utf-16-le'):
            logger.info('Parsing [{}] {} [{:x}]'.format(cnt, name, s.bytepos))
            items = s.readstrings(size, cnt, encoding)
            logger.debug(repr(items))
            return items

        menu_items = parse_string_section('menu items', 0x100, self.cnt_menu)
        unk2_items = parse_string_section('Unknown 2', 0x50, self.cnt_38)
        var_items  = parse_string_section('Variables', 0x80, self.cnt_var)
        fn_items   = parse_mixed_section('Functions', 0x60, 8,  self.cnt_fn)
        unk_structs = parse_string_section('structs', 0x100, self.cnt_10)
        self.contexts = ContextInformation.fromstream(s, self.cnt_18)
        print('Finished parsing contexts')
        cur_size = 0
        self.context_entries = []
        while cur_size < self.cnt_1c:
            context = ContextEntry.fromstream(s)
            self.context_entries.append(context)
            cur_size += context.size
        logger.debug('Finished parsing. Num contexts={}, Num entries={}, Num functions={}'.format(
            len(self.contexts), len(self.context_entries), len(menu_items)))


g = GSCEFile.fromfile('PersonA.gsce')

