#
# Extract platform data from CCC
# Copyright (c) 2018 vit9696
#

import ida_bytes
import struct

def readaddr(ea):
    a = ida_bytes.get_bytes(ea, 8)
    return None if a == BADADDR else struct.unpack("L", a)[0]

def readstr(ea, l=256):
    if ea == BADADDR:
        return None

    str = ""
    while 1:
        c = ida_bytes.get_bytes(ea, 1)
        if c == BADADDR and str == "":
            return None
        elif c in [BADADDR, "\0"]:
            return str
        str += c
        ea += 1
        if len(str) > l:
            return str

base = get_name_ea(0, "_show")
count = 0
base = get_name_ea(0, "_show")
while 1:
    s = readstr(readaddr(base))
    if s is None:
        break
    info = s.split('-', 1)
    s = readstr(readaddr(base))
    base += 8
    count += 1;

    name = get_name(base)
    if name not in [None, "", "_show"]:
        break
base = get_name_ea(0, "_show")
base
base = get_name_ea(0, "_ApplePlatformData")
base = get_name_ea(0, "_show")
while 1:
    productName     = readstr(readaddr(base+0))
    firmwareVersion = readstr(readaddr(base+8))  # board version
    boardID         = readstr(readaddr(base+16))
    productFamily   = readstr(readaddr(base+24))
    systemVersion   = readstr(readaddr(base+32)) # bios version
    serialNumber    = readstr(readaddr(base+40))
    chassisAsset    = readstr(readaddr(base+48))
    smcRevision     = struct.unpack("BBBBBB", ida_bytes.get_bytes(base+56, 6))
    unknownValue    = readaddr(base+64)
    smcBranch       = readstr(readaddr(base+72))
    smcPlatform     = readstr(readaddr(base+80))
    smcConfig       = readaddr(base+88)

    if (
        productName is None
        or firmwareVersion is None
        or boardID is None
        or productFamily is None
        or systemVersion is None
        or serialNumber is None
        or chassisAsset is None
        or smcBranch is None
        or smcConfig is None
    ):
        break

    productName     = readstr(readaddr(base+0))
    productName     = readstr(readaddr(base+0))
    productName     = readstr(readaddr(base+0))
    base += 0x60

    name = get_name(base)
    if name not in [None, "", "_ApplePlatformData"]:
        break
base = get_name_ea(0, "_show")
base = get_name_ea(0, "_ModelCode")
base = get_name_ea(0, "_show")
while 1:
    s = readstr(readaddr(base))
    if s is None:
        break

    s = readstr(readaddr(base))
    base += 8

    name = get_name(base)
    if name not in [None, "", "_ModelCode"]:
        break
base = get_name_ea(0, "_show")
