
# -*- coding: utf-8 -*-

import sys
import os
import binascii
import zlib
import struct


def main():
    argCount = len(sys.argv)
    if argCount < 2 :
        print("repair dexFile checkSum need filePath!")
        return
    filePath = sys.argv[1]
    try:
        file_size = os.path.getsize(filePath)
    except FileNotFoundError:
        print("dexFile NotFound!")
        return

    print("dexFile size = 0x%X" % file_size)

    with open(filePath, 'rb+') as f:
        f.seek(0x8)

        checksum_bytes = binascii.b2a_hex(f.read(4)[::-1])
        print(checksum_bytes)
        old_checksum = checksum_bytes.decode()
        print("dexFile old checkSum = 0x%X" % int(old_checksum, 16))
 
        f.seek(0xc)
        bytes = f.read(file_size - 0xc)
        new_checksum = zlib.adler32(bytes)
        print("dexFile new checkSum = 0x%X" % new_checksum)

        data = struct.pack('<L', new_checksum)
        f.seek(0x8)
        f.write(data)
        print('repair checkSum ok!')


if __name__ == "__main__":
    main()
