# -*- coding: utf-8 -*-

import sys
import mmap
import struct
import binascii
import zlib

class DexFile(object):
    def __init__(self, filePath):
        self.dexFilePath = filePath

        try:
            with open(self.dexFilePath, 'rb') as f:
                self.data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ | mmap.ACCESS_COPY)
                bytes = self.data[0xc:]
                self.checkSum = zlib.adler32(bytes)
        except FileNotFoundError :
            print("No such file or directory: '%s'" % self.dexFilePath)
            return
        self.isDexFile = self.check_file_format()
        if self.isDexFile :
            self.init_DexHeader()
    
    # check dexFile format
    def check_file_format(self):
        file_magic = self.data[0:8]
        if file_magic != b'dex\n035\x00':
            print("dexFile magic flag is %s, required 'dex\\n035\\x00'" % file_magic)
            return False
        
        file_checkSum = struct.unpack('<L', self.data[0x8:0xc])[0]
        if file_checkSum != self.checkSum:
            print("dexFile checkSum should 0x%X but 0x%x" % (self.checkSum, file_checkSum))
            return False

        file_headerSize = struct.unpack('<L', self.data[0x24:0x28])[0]
        if file_headerSize != 0x70:
            print("dexFile headerSize required 0x70")
            return False

        file_endian_tag = struct.unpack('<L', self.data[0x28:0x2c])[0]
        if file_endian_tag != 0x12345678:
            print("dexFile endian_tag required 0x12345678")
            return False

        return True

    # get DexHeader struct data
    def init_DexHeader(self):
        self.header_data = {
            "magic" : self.data[0:8],
            "checksum" : struct.unpack('<L', self.data[8:0xc])[0],   #L --> unsigned long   < --> little-endian
            "signature" : self.data[0xc:0x20],
            "file_size" : struct.unpack('<L', self.data[0x20:0x24])[0],
            "headr_size" : struct.unpack('<L', self.data[0x24:0x28])[0],
            "endian_tag" : struct.unpack('<L', self.data[0x28:0x2c])[0],
            "linksize" : struct.unpack('<L', self.data[0x2c:0x30])[0],
            "linkoff" : struct.unpack('<L', self.data[0x30:0x34])[0],
            'map_off': struct.unpack('<L', self.data[0x34:0x38])[0],
            'string_ids_size': struct.unpack('<L', self.data[0x38:0x3C])[0],
            'string_ids_off': struct.unpack('<L', self.data[0x3C:0x40])[0],
            'type_ids_size': struct.unpack('<L', self.data[0x40:0x44])[0],
            'type_ids_off': struct.unpack('<L', self.data[0x44:0x48])[0],
            'proto_ids_size': struct.unpack('<L', self.data[0x48:0x4C])[0],
            'proto_ids_off': struct.unpack('<L', self.data[0x4C:0x50])[0],
            'field_ids_size': struct.unpack('<L', self.data[0x50:0x54])[0],
            'field_ids_off': struct.unpack('<L', self.data[0x54:0x58])[0],
            'method_ids_size': struct.unpack('<L', self.data[0x58:0x5C])[0],
            'method_ids_off': struct.unpack('<L', self.data[0x5C:0x60])[0],
            'class_defs_size': struct.unpack('<L', self.data[0x60:0x64])[0],
            'class_defs_off': struct.unpack('<L', self.data[0x64:0x68])[0],
            'data_size': struct.unpack('<L', self.data[0x68:0x6C])[0],
            'data_off': struct.unpack('<L', self.data[0x6C:0x70])[0]
        }

    # print DexHeader struct data
    def print_dexHeader(self):
        print('[+] magic:\t\t%s' % self.header_data["magic"])
        print('[+] checksum:\t\t0x%X' % self.header_data["checksum"])
        print('[+] signature:\t\t%s' % (binascii.b2a_hex(self.header_data["signature"])))
        print('[+] file_size:\t\t0x%X' % self.header_data["file_size"])
        print('[+] headr_size:\t\t0x%X' % self.header_data["headr_size"])
        print('[+] endian_tag:\t\t0x%X' % self.header_data["endian_tag"])
        print('[+] linksize:\t\t0x%X' % self.header_data["linksize"])
        print('[+] linkoff:\t\t0x%X' % self.header_data["linkoff"])
        print('[+] map_off:\t\t0x%X' % self.header_data["map_off"])
        print('[+] string_ids_size:\t0x%X' % self.header_data["string_ids_size"])
        print('[+] string_ids_off:\t0x%X' % self.header_data["string_ids_off"])
        print('[+] type_ids_size:\t0x%X' % self.header_data["type_ids_size"])
        print('[+] type_ids_off:\t0x%X' % self.header_data["type_ids_off"])
        print('[+] proto_ids_size:\t0x%X' % self.header_data["proto_ids_size"])
        print('[+] proto_ids_off:\t0x%X' % self.header_data["proto_ids_off"])
        print('[+] field_ids_size:\t0x%X' % self.header_data["field_ids_size"])
        print('[+] field_ids_off:\t0x%X' % self.header_data["field_ids_off"])
        print('[+] method_ids_size:\t0x%X' % self.header_data["method_ids_size"])
        print('[+] method_ids_off:\t0x%X' % self.header_data["method_ids_off"])
        print('[+] class_defs_size:\t0x%X' % self.header_data["class_defs_size"])
        print('[+] class_defs_off:\t0x%X' % self.header_data["class_defs_off"])
        print('[+] data_size:\t\t0x%X' % self.header_data["data_size"])
        print('[+] data_off:\t\t0x%X' % self.header_data["data_off"])
        pass


    '''
    # parser uleb128 format:
    # param:
    #   offset --> file offset
    # returns:
    #   uleb128_count --> the uleb128 byte count
    #   uleb128_data  --> the uleb128 data
    '''
    def uleb128_value(self, offset):
        tmp = 1
        uleb128_count = 0
        uleb128_data = 0
        while tmp:
            tmp_data = self.data[offset]  & 0x7f
            uleb128_data = uleb128_data | (tmp_data << (7 * uleb128_count))

            uleb128_count = uleb128_count + 1
            tmp = self.data[offset] & 0x80
            offset = offset + 1
        return uleb128_count, uleb128_data


    '''
    # parser sleb128 format:
    # param:
    #   offset --> file offset
    # returns:
    #   sleb128_count --> the sleb128 byte count
    #   sleb128_data  --> the sleb128 data
    '''
    def sleb128_value(self, offset):
        tmp = 1
        sleb128_count = 0
        sleb128_data = 0
        while tmp:
            tmp_data = self.data[offset]  & 0x7f
            tmp_sleb128_data = sleb128_data
            sleb128_data = sleb128_data | (tmp_data << (7 * sleb128_count))

            sleb128_count = sleb128_count + 1
            tmp = self.data[offset] & 0x80
            offset = offset + 1
        
        if ((tmp_data & 0x40) >> 6) != 0:
            tmp_data = self.data[offset - 1]  | 0x80
            sleb128_data = tmp_sleb128_data | (tmp_data << (7 * (sleb128_count - 1)))
            return sleb128_count, self.getSignedNumber(sleb128_data, sleb128_count * 8)

        return sleb128_count, sleb128_data


    '''
    # get str size from uleb128 format:
    # param:
    #   offset --> str offset
    # returns:
    #   leb128_count --> the uleb128 byte count
    #   str_size     --> the str size
    '''
    def get_string_size(self, offset):
        uleb128_count, str_size = self.uleb128_value(offset)
        return uleb128_count, str_size + 1   #  + '\0'


    # get field count from uleb128 format
    def get_fields_count(self, offset):
        uleb128_count, fields_count = self.uleb128_value(offset)
        return uleb128_count, fields_count

    # get method count from uleb128 format
    def get_methods_count(self, offset):
        uleb128_count, methods_count = self.uleb128_value(offset)
        return uleb128_count, methods_count


    def get_fileData(self):
        return self.data

    def get_headerData(self):
        return self.header_data
    
    def get_checkSum(self):
        return "0x%X" % self.header_data['checksum']
    
    def get_fileSize(self):
        return self.header_data['file_size']


    # get dexFile map list
    def get_map_list(self):
        map_list = []
        map_list_off = self.header_data['map_off']
        map_list_size = struct.unpack('<L', self.data[map_list_off : map_list_off + 4])[0]
        map_list_off += 4
        for i in range(map_list_size):
            type = struct.unpack('<H', self.data[map_list_off + i * 12 : map_list_off + i * 12 + 2])[0]
            size = struct.unpack('<L', self.data[map_list_off + i * 12 + 4 : map_list_off + i * 12 + 8])[0]
            offset = struct.unpack('<L', self.data[map_list_off + i * 12 + 8: map_list_off + i * 12 + 12])[0]
            map_list.append({'type': hex(type), 'size': hex(size), 'offset': hex(offset)})
        
        return map_list


    # get dexFile string list
    def get_string_ids(self):
        strings = []
        string_ids_off = self.header_data['string_ids_off']
        string_ids_size = self.header_data['string_ids_size']
              
        for i in range(string_ids_size):
            str_offset = struct.unpack('<L', self.data[string_ids_off + i * 4 : string_ids_off + i * 4 + 4])[0]
            leb128_count, str_size = self.get_string_size(str_offset)
           
            str = self.data[str_offset + leb128_count: str_offset + str_size]
            strings.append(str)
            pass
        
        return strings


    # get dexFile type list
    def get_type_ids(self):
        type_ids = []
        type_ids_off = self.header_data['type_ids_off']
        type_ids_size = self.header_data['type_ids_size']
        #strings = self.get_string_ids()

        for i in range(type_ids_size):
            index = struct.unpack('<L', self.data[type_ids_off + i * 4 : type_ids_off + i * 4 + 4])[0]
            #print(strings[index].decode())
            #typeids.append(strings[index].decode())
            type_ids.append(hex(index))

        return type_ids


    '''
    # get dexFile proto list:
    #   shorty_idx       uint --> string list index
    #   return_type_idx  uint --> type list index
    #   parameters_off   uint --> struct type_list
    '''
    def get_proto_ids(self):
        proto_ids = []
        proto_ids_off = self.header_data['proto_ids_off']
        proto_ids_size = self.header_data['proto_ids_size']

        for i in range(proto_ids_size):
            shorty_idx = struct.unpack('<L', self.data[proto_ids_off + i * 12 : proto_ids_off + i * 12 + 4])[0]
            return_type_idx = struct.unpack('<L', self.data[proto_ids_off + i * 12 + 4 : proto_ids_off + i * 12 + 8])[0]
            parameters_off = struct.unpack('<L', self.data[proto_ids_off + i * 12 + 8 : proto_ids_off + i * 12 + 12])[0]
            proto_ids.append({'shorty_idx': hex(shorty_idx), 'return_type_idx': hex(return_type_idx), 'parameters_off': hex(parameters_off)})
            
        return proto_ids

    '''
    # get dexFile field list:
    #   class_idx ushort --> type list index
    #   type_idx  ushort --> type list index
    #   name_idx  uint   --> string list index
    '''
    def get_field_ids(self):
        field_ids = []
        field_ids_off = self.header_data['field_ids_off']
        field_ids_size = self.header_data['field_ids_size']

        for i in range(field_ids_size):
            class_idx = struct.unpack('<H', self.data[field_ids_off + i * 8 : field_ids_off + i * 8 + 2])[0]
            type_idx = struct.unpack('<H', self.data[field_ids_off + i * 8 + 2 : field_ids_off + i * 8 + 4])[0]
            name_idx = struct.unpack('<L', self.data[field_ids_off + i * 8 + 4 : field_ids_off + i * 8 + 8])[0]
            field_ids.append({'class_idx': hex(class_idx), 'type_idx': hex(type_idx), 'name_idx': hex(name_idx)})
            
        return field_ids


    '''
    # get dexFile nethod list:
    #   class_idx ushort  --> type list index
    #   proto_idx ushort  --> proto list index
    #   name_idx  uint    --> string list index
    '''
    def get_method_ids(self):
        method_ids = []
        method_ids_off = self.header_data['method_ids_off']
        method_ids_size = self.header_data['method_ids_size']

        for i in range(method_ids_size):
            class_idx = struct.unpack('<H', self.data[method_ids_off + i * 8 : method_ids_off + i * 8 + 2])[0]
            proto_idx = struct.unpack('<H', self.data[method_ids_off + i * 8 + 2 : method_ids_off + i * 8 + 4])[0]
            name_idx = struct.unpack('<L', self.data[method_ids_off + i * 8 + 4 : method_ids_off + i * 8 + 8])[0]
            method_ids.append({'class_idx': hex(class_idx), 'proto_idx': hex(proto_idx), 'name_idx': hex(name_idx)})
            
        return method_ids


    '''
    get dexFile class_defs data:
      class_idx          uint --> type list index
      access_flags       uint --> flag
      superclass_idx     uint --> type list index
      interfaces_off     uint --> flag
      source_file_idx    uint --> string list index
      annotations_off    uint --> 
      class_data_off     uint --> struct class_data_item
      static_values_off  uint --> 
    '''
    def get_classdef_data(self):
        classdef_ids = []
        class_defs_off = self.header_data['class_defs_off']
        class_defs_size = self.header_data['class_defs_size']

        for i in range(class_defs_size):
            class_idx = struct.unpack('<L', self.data[class_defs_off + i * 32 : class_defs_off + i * 32 + 4])[0]
            access_flags = struct.unpack('<L', self.data[class_defs_off + i * 32 + 4: class_defs_off + i * 32 + 8])[0]
            superclass_idx = struct.unpack('<L', self.data[class_defs_off + i * 32 + 8: class_defs_off + i * 32 + 12])[0]
            interfaces_off = struct.unpack('<L', self.data[class_defs_off + i * 32 + 12: class_defs_off + i * 32 + 16])[0]
            source_file_idx = struct.unpack('<L', self.data[class_defs_off + i * 32 + 16: class_defs_off + i * 32 + 20])[0]
            annotations_off = struct.unpack('<L', self.data[class_defs_off + i * 32 + 20: class_defs_off + i * 32 + 24])[0]
            class_data_off = struct.unpack('<L', self.data[class_defs_off + i * 32 + 24: class_defs_off + i * 32 + 28])[0]
            static_values_off = struct.unpack('<L', self.data[class_defs_off + i * 32 + 28: class_defs_off + i * 32 + 32])[0]

            classdef_ids.append({'class_idx': hex(class_idx), 'access_flags': hex(access_flags), 'superclass_idx': hex(superclass_idx),
            'interfaces_off': hex(interfaces_off),'source_file_idx': hex(source_file_idx),'annotations_off': hex(annotations_off),
            'class_data_off': hex(class_data_off),'static_values_off': hex(static_values_off),})

        return classdef_ids


    '''
    # get dexFile class_data 
    # param:
    #   offset --> class_data_off, the member of class_defs
    # return:
    #   return dict 
    # 
    # encoded_field:
    #   field_idx_diff  uleb128   field list index
    #   access_flags    uleb128
    #
    # encoded_method：
    #   method_idx_diff uleb128   method list index
    #   access_flags    uleb128
    #   code_off        uleb128   code_item offset
    '''
    def get_class_data(self, offset):
        static_fields   = []
        instance_fields = []
        direct_methods  = []
        virtual_methods = []

        static_fields_size , static_fields_count = self.get_fields_count(offset)
        offset = offset + static_fields_size

        instance_fields_size, instance_fields_count = self.get_fields_count(offset)
        offset = offset + instance_fields_size

        direct_methods_size, direct_methods_count = self.get_methods_count(offset)
        offset = offset + direct_methods_size

        virtual_methods_size, virtual_methods_count = self.get_methods_count(offset)
        offset = offset + virtual_methods_size

        byte_count = 0
        for i in range(static_fields_count):
            byte_count, field_idx_diff = self.uleb128_value(offset)
            offset += byte_count
            byte_count, access_flags = self.uleb128_value(offset)
            offset += byte_count
            static_fields.append({"field_idx_diff" : hex(field_idx_diff), 'access_flags': hex(access_flags)})
        #print(static_fields)

        byte_count = 0
        for i in range(instance_fields_count):
            byte_count, field_idx_diff = self.uleb128_value(offset)
            offset += byte_count
            byte_count, access_flags = self.uleb128_value(offset)
            offset += byte_count
            instance_fields.append({"field_idx_diff" : hex(field_idx_diff), 'access_flags': hex(access_flags)})
        #print(instance_fields)

        byte_count = 0
        for i in range(direct_methods_count):
            byte_count, method_idx_diff = self.uleb128_value(offset)
            offset += byte_count
            byte_count, access_flags = self.uleb128_value(offset)
            offset += byte_count
            byte_count, code_off = self.uleb128_value(offset)
            offset += byte_count
            direct_methods.append({"method_idx_diff" : hex(method_idx_diff), 'access_flags': hex(access_flags), 'code_off': hex(code_off)})
        #print(direct_methods)

        byte_count = 0
        for i in range(virtual_methods_count):
            byte_count, method_idx_diff = self.uleb128_value(offset)
            offset += byte_count
            byte_count, access_flags = self.uleb128_value(offset)
            offset += byte_count
            byte_count, code_off = self.uleb128_value(offset)
            offset += byte_count
            virtual_methods.append({"method_idx_diff" : hex(method_idx_diff), 'access_flags': hex(access_flags), 'code_off': hex(code_off)})
        #print(virtual_methods)

        return {'static_fields': static_fields,
                'instance_fields': instance_fields,
                'direct_methods': direct_methods,
                'virtual_methods': virtual_methods}

    '''
    # get dexFile code_item 
    # param:
    #   offset --> code_item_off, the member of class_data_off
    # return:
    #   return dict 
    # 
    # code_item format:
    #   registers_size  ushort
    #   ins_size        ushort
    #   outs_size       ushort
    #   tries_size      ushort
    #   debug_info_off  uint
    #   insns_size      uint 
    #   insns           ushort[insns_size]
    #   padding         ushort 
    #   tries           try_item[tries_size]
    #   handlers        encoded_catch_handler_list
    #
    '''
    def get_code_item(self, code_item_off):
        registers_size = struct.unpack('<H', self.data[code_item_off : code_item_off + 2])[0]
        ins_size = struct.unpack('<H', self.data[code_item_off + 2 : code_item_off + 4])[0]
        outs_size = struct.unpack('<H', self.data[code_item_off + 4 : code_item_off + 6])[0]
        tries_size = struct.unpack('<H', self.data[code_item_off + 6 : code_item_off + 8])[0]
        debug_info_off = struct.unpack('<L', self.data[code_item_off + 8 : code_item_off + 12])[0]
        insns_size = struct.unpack('<L', self.data[code_item_off + 12 : code_item_off + 16])[0]

        # This padding element is only present if tries_size is non-zero and insns_size is odd.
        if (tries_size != 0) and (insns_size % 2) != 0:
            padding = True
        else :
            padding = False
        
        # tries and handlers is only present if tries_size is non-zero
        if tries_size != 0 :
            if padding:
                m = 2
            else :
                m = 0
            try_item_off = code_item_off + 16 + insns_size * 2 + m
            try_item_size = tries_size * 8
            catch_handler_list_offset = try_item_off + try_item_size
            catch_handler_list_size = self.get_catch_handler_list_size(catch_handler_list_offset)

        else:
            try_item_off = 0
            try_item_size = 0
            catch_handler_list_offset = 0

        
        code_item = {
            "registers_size" : hex(registers_size),
            "ins_size" : hex(ins_size),
            "outs_size" : hex(outs_size),
            "tries_size" : hex(tries_size),
            "debug_info_off" : hex(debug_info_off),
            "insns_size" : hex(insns_size),
            "insns" : self.data[code_item_off + 16 : code_item_off + 16 + insns_size * 2],
            "padding" : padding,
            "try_item_off" : hex(try_item_off),
            "try_item_size" : hex(try_item_size),
            "catch_handler_list_offset" : hex(catch_handler_list_offset),
            "catch_handler_list_size" : hex(catch_handler_list_size)
        }
        return code_item


    '''
    # get dexFile catch_handler_list size
    # param:
    #   offset --> catch_handler_list offset
    # return:
    #   return size 
    # 
    '''    
    def get_catch_handler_list_size(self, offset):
        byte_count, catch_handler_list_count = self.uleb128_value(offset)
        offset = offset + byte_count

        catch_handler_list_size = byte_count

        for i in range(catch_handler_list_count):
            tmp = 0
            handler_offset = offset

            '''
            # number of catch types in this list
            #   0 --> finaly but no catches
            #   2 --> 2 catcher but no finaly
            #  -1 --> 1 catcher along with a finaly
            '''
            catch_number_byte_count, catch_number = self.sleb128_value(handler_offset)
            handler_offset = handler_offset + catch_number_byte_count

            tmp += catch_number_byte_count

            if catch_number == 0:
                catch_all_addr_byte_count, catch_all_addr_data = self.uleb128_value(handler_offset)
                tmp += catch_all_addr_byte_count    
            elif catch_number > 0:
                m = catch_number
                for j in range(m):
                    type_idx_byte_count, type_idx_data = self.uleb128_value(handler_offset)
                    handler_offset += type_idx_byte_count
                    addr_byte_count, addr_data = self.uleb128_value(handler_offset)
                    handler_offset += addr_byte_count

                    tmp += type_idx_byte_count
                    tmp += addr_byte_count
            else:
                m = abs(catch_number) 
                for j in range(m):
                    type_idx_byte_count, type_idx_data = self.uleb128_value(handler_offset)
                    handler_offset += type_idx_byte_count
                    addr_byte_count, addr_data = self.uleb128_value(handler_offset)
                    handler_offset += addr_byte_count

                    tmp += type_idx_byte_count
                    tmp += addr_byte_count

                catch_all_addr_byte_count, catch_all_addr_data = self.uleb128_value(handler_offset)
                tmp += catch_all_addr_byte_count 

            offset += tmp
            catch_handler_list_size += tmp

        return catch_handler_list_size
    
    
    # unsigned to signed
    def getSignedNumber(self, number, bitLength):
        mask = pow(2,bitLength) - 1
        if number & (1 << (bitLength - 1)):
            return number | ~mask
        else:
            return number & mask

    # signed to unsigned
    def getUnsignedNumber(self, number, bitLength):
        mask = pow(2,bitLength) - 1
        return number & mask


    pass




def main():
    argCount = len(sys.argv)
    if argCount < 2 :
        print("Parser dexFile need filePath!")
        return
    
    filePath = sys.argv[1]
    dex = DexFile(filePath)
    dex.print_dexHeader()

    #sleb128_count, sleb128_data = dex.sleb128_value(0x1D029)


    # result = dex.get_code_item(0x1CD90)
    # print(result)

    result = dex.get_code_item(0x1C294)
    print(result)
    # result = dex.get_map_list()
    # print(result)

    # result = dex.get_class_data(0x365db2)
    # print(result)

    # dex.get_type_ids()
    # result = dex.get_classdef_data()
    # print(result)




if __name__ == "__main__":
    main()


