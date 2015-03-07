# -*- coding: utf-8 -*-
"""
Created on Tue Feb 17 16:42:59 2015

@author: burningcodes
"""

import struct
import binascii
import hashlib
import zlib
import random

class DexFile:
    def __init__(self,filepath):
        self.dex = open(filepath,"r+")#不能用rw ，同时读写要用r+
        self.string_table = []
        self.type_table = []
        self.proto_table = []
        self.field_table = []
        self.method_table = []
        self.map_type = {0x0:"header_item",
                     0x1:"string_id_item",
                     0x2:"type_id_item",
                     0x3:"proto_id_item",
                     0x4:"field_id_item",
                     0x5:"method_id_item",
                     0x6:"class_def_item",
                     0x1000:"map_list",
                     0x1001:"type_list",
                     0x1002:"annotation_set_ref_list",
                     0x1003:"annotation_set_item",
                     0x2000:"class_data_item",
                     0x2001:"code_item",
                     0x2002:"string_data_item",
                     0x2003:"debug_info_item",
                     0x2004:"annotation_item",
                     0x2005:"encoded_array_item",
                     0x2006:"annotations_directory_item"}
        
        self.randomstr = ["a","b","c","d","e","f","g","h","i","j",\
                          "k","l","m","n","o","p","q","r","s","t",\
                          "u","v","w","x","y","z",\
                          "A","B","C","D","E","F","G","H","I","J",\
                          "K","L","M","N","O","P","Q","R","S","T",\
                          "U","V","W","X","Y","Z",\
                          "0","1","2","3","4","5","6","7","8","9"]# 62
        
        self.usedstr = {} #混淆的字符串不能重复  用字典来判断
        
        
    def ReadDexHeader(self):
        print "----------------read Header-----------------------------"
        self.magic = struct.unpack("4s",self.dex.read(4))[0]
        print "magic code:",self.magic,#加逗号去掉最后的自动换行        
        if self.magic != "dex\n":
            print "the file is not a dex file"
            self.CloseDexFile()
            exit(-1)
            return
            
        self.version = struct.unpack("4s",self.dex.read(4))[0]
        print "version:",self.version
        
        #用adler32算法对这个字段之后的所有数据做的检验码，来验证这个dex文件是否损坏
        self.checksum = struct.unpack("i",self.dex.read(4))[0]       
        print "checksum:",self.checksum

        #dex文件的签名值（是对这个字段之后的所有数据做的签名，用来唯一的标识这个dex文件）        
        self.sig = struct.unpack("20s",self.dex.read(20))[0]
        #将字符串以16进制打印出时用 binascii库  
        print "signature:", str(binascii.b2a_hex(self.sig))        
        
        
        self.filesize = struct.unpack("I",self.dex.read(4))[0]  
        print "filesize:",self.filesize

        self.headersize = struct.unpack("I",self.dex.read(4))[0]  
        print "headersize:",self.headersize
        
        #默认情况下是以小顶端的方式存 小顶端时读出0x12345678,大顶端时读出0x78563412
        self.endiantag = struct.unpack("I",self.dex.read(4))[0]  
        print "endiantag:",hex(self.endiantag)
        
        self.link_size = struct.unpack("I",self.dex.read(4))[0]  
        print "link_size:",self.link_size
        
        self.link_off = struct.unpack("I",self.dex.read(4))[0]  
        print "link_off:",self.link_off,"(",hex(self.link_off),")"
        
        self.map_off = struct.unpack("I",self.dex.read(4))[0]  
        print "map_off:",self.map_off,"(",hex(self.map_off),")"
        
        self.string_num = struct.unpack("I",self.dex.read(4))[0]  
        print "string_num:",self.string_num
        
        self.string_table_off = struct.unpack("I",self.dex.read(4))[0]  
        print "string_table_off:",self.string_table_off,"(",hex(self.string_table_off),")"
        
        self.type_num = struct.unpack("I",self.dex.read(4))[0]  
        print "type_num:",self.type_num
        
        self.type_table_off = struct.unpack("I",self.dex.read(4))[0]  
        print "type_table_off:",self.type_table_off,"(",hex(self.type_table_off),")"
        
        self.proto_num = struct.unpack("I",self.dex.read(4))[0]  
        print "proto_num:",self.proto_num
        
        self.proto_off = struct.unpack("I",self.dex.read(4))[0]  
        print "proto_off:",self.proto_off,"(",hex(self.proto_off),")"
                
        self.field_num = struct.unpack("I",self.dex.read(4))[0]  
        print "field_num:",self.field_num
        
        self.field_off = struct.unpack("I",self.dex.read(4))[0]  
        print "field_off:",self.field_off,"(",hex(self.field_off),")"
        
        self.method_num = struct.unpack("I",self.dex.read(4))[0]  
        print "method_num:",self.method_num
        
        self.method_off = struct.unpack("I",self.dex.read(4))[0]  
        print "method_off:",self.method_off,"(",hex(self.method_off),")"
        
        self.class_def_size = struct.unpack("I",self.dex.read(4))[0]  
        print "class_def_size:",self.class_def_size      
        
        self.class_def_off = struct.unpack("I",self.dex.read(4))[0]  
        print "class_def_off:",self.class_def_off,"(",hex(self.class_def_off),")"

        self.data_size = struct.unpack("I",self.dex.read(4))[0]  
        print "data_size:",self.data_size
        
        self.data_off = struct.unpack("I",self.dex.read(4))[0]  
        print "data_off:",self.data_off,"(",hex(self.data_off),")"
        



    def ReadStringTable(self):
        print "----------------read String-----------------------------"
        
        self.dex.seek(self.string_table_off,0)

        count = 0
        while(count < self.string_num):
            #unpack返回的是一个元组，所以要用[0]来取出元组中的第一个元素
            self.string_table.append(struct.unpack("I",self.dex.read(4))[0])
            count+=1
        ##############################
            
      
      
    #type table的内容全都指向string table
    def ReadTypeTable(self):
        print "----------------read Type-----------------------------"

        count = 0
        self.dex.seek(self.type_table_off)
        while(count < self.type_num):
            self.type_table.append(struct.unpack("I",self.dex.read(4))[0])
            count+=1
        

    
    #变量
    def ReadFieldsTable(self):
        print "----------------read Fields-----------------------------"
        count = 0
        self.dex.seek(self.field_off)
        print "Fields:",self.field_num
        while(count < self.field_num):
            class_idx,type_idx,name_idx = struct.unpack("HHI",self.dex.read(8))
            
            self.field_table.append([class_idx,type_idx,name_idx])
            count+=1
    
    #函数
    def ReadMethodTable(self):
        print "----------------read Method-----------------------------"
        count = 0
        self.dex.seek(self.method_off)
        print "Method:",self.method_num
        while(count < self.method_num):
            class_idx,proto_idx,name_idx = struct.unpack("HHI",self.dex.read(8))
           
            self.method_table.append([class_idx,proto_idx,name_idx])
            count+=1        
    
    
    def ConfuseClass(self):
        count = 0
        
        print "----------------read Class-----------------------------"
        print "Class:",self.class_def_size
        while(count < self.class_def_size):
            self.dex.seek(self.class_def_off + count*32)            
       
            class_idx,\
            access_flags,\
            superclass_idx,\
            interfaces_off,\
            source_file_idx,\
            annotations_off,\
            class_data_off,\
            static_values_off = struct.unpack("IIIIIIII",self.dex.read(32))
            #print "Class",count,self.types[class_idx]
            
            count+=1
            
            ######################
            # 判断是否能被混淆
            #####################################
            print class_idx
            print self.type_table[class_idx]
            classnameoff = self.string_table[self.type_table[class_idx]]
            self.dex.seek(classnameoff,0)
            strlen = self.DecUnsignedLEB128(self.dex)
            #用tell来获取当前位置
            classnameoff = self.dex.tell()
            
            #print "len:",strlen
            #读取不定长字符串
            classname = self.dex.read(strlen)
            
            
            if superclass_idx != 0xffffffff:
                #有父类
                superclassoff = self.string_table[self.type_table[superclass_idx]]
                self.dex.seek(superclassoff,0)
                strlen2 = self.DecUnsignedLEB128(self.dex)
                #print  "super len:",strlen2
                superclass = self.dex.read(strlen2)
            else:
                #没有父类
                superclass = ""
                
            
            if self.ClassCanBeConfused(classname,superclass) == False:
                continue
            
            #从后面开始找/
            idx = classname.rfind("/")
            print "classname",classname,"idx",idx
            #没找到说明是这样： Lsumclass; 这时idx指向s 即idx=1
            if idx == -1:
                idx = 1
            #print "ll:",strlen    
            
            #比如 Lclassname/main; 从/之后的m到n
            strlen = strlen - idx - 2#包名不能被混淆 去除/和;
            #print "len",strlen
            #混淆类名
            self.DoConfuse(classnameoff + idx + 1,strlen)#/后面一个开始
            
            ######################################
            
            
            
            
            
            #class_data_off为0表示此类没有类数据（是接口）
            if class_data_off == 0:
                continue
            #获取类数据，获取该类定义的方法和字段
            self.dex.seek(class_data_off)
            static_fields_size = self.DecUnsignedLEB128(self.dex)
            instance_fields_size = self.DecUnsignedLEB128(self.dex)  
            direct_methods_size = self.DecUnsignedLEB128(self.dex)
            virtual_methods_size = self.DecUnsignedLEB128(self.dex)
            
            print "static_fields_size:",static_fields_size
            field_idx = 0
            while(static_fields_size > 0):       
                field_idx_diff = self.DecUnsignedLEB128(self.dex)
                access_flags = self.DecUnsignedLEB128(self.dex)
                static_fields_size-=1
                savedaddr = self.dex.tell()#保存当前地址
                
                #取出field
                name_idx = self.field_table[field_idx + field_idx_diff][2]
                self.dex.seek(self.string_table[name_idx],0)
                strlen = self.DecUnsignedLEB128(self.dex)
                #用tell来获取当前位置
                fieldoff = self.dex.tell()
                
                #print "filed:",self.dex.read(strlen),"len:",strlen
                
                #混淆field
                self.DoConfuse(fieldoff,strlen)
            
            
                field_idx+=field_idx_diff    
                
                self.dex.seek(savedaddr)#恢复地址
                
                #do sth
            
            field_idx = 0
            print "instance_fields_size",instance_fields_size
            while(instance_fields_size > 0):
                field_idx_diff = self.DecUnsignedLEB128(self.dex)
                access_flags = self.DecUnsignedLEB128(self.dex)
                instance_fields_size-=1
                
                savedaddr = self.dex.tell()#保存当前地址
                
                #取出field
                name_idx = self.field_table[field_idx + field_idx_diff][2]
                self.dex.seek(self.string_table[name_idx],0)
                strlen = self.DecUnsignedLEB128(self.dex)
                #用tell来获取当前位置
                fieldoff = self.dex.tell()
                #混淆field
                #print "filed:",self.dex.read(strlen),"len:",strlen
                self.DoConfuse(fieldoff,strlen)
                
                
                field_idx+=field_idx_diff  
                
                self.dex.seek(savedaddr)#恢复地址
                
                #do sth
            

            method_idx = 0
            print "direct_methods_size",direct_methods_size
            while(direct_methods_size > 0):    
                method_idx_diff = self.DecUnsignedLEB128(self.dex)
                access_flags = self.DecUnsignedLEB128(self.dex)
                code_off = self.DecUnsignedLEB128(self.dex)
                direct_methods_size-=1
                #第一次循环时method_idx_diff直接指向method table中对应的项
                #从第二次开始method_idx_diff就是与前一次的偏移值，方法在这个列表
                #中一定是递增的
                
                savedaddr = self.dex.tell()#保存当前地址
                
                #取出method
                name_idx = self.method_table[method_idx + method_idx_diff][2]
                self.dex.seek(self.string_table[name_idx],0)
                strlen = self.DecUnsignedLEB128(self.dex)
                #用tell来获取当前位置
                methodoff = self.dex.tell()
                #混淆field
                methodname = self.dex.read(strlen)
                print "filed:",methodname,"len:",strlen
                
                
                #不能混淆init函数
                if methodname != "<init>":
                    self.DoConfuse(methodoff,strlen)
                
                
                method_idx+=method_idx_diff             
                
                self.dex.seek(savedaddr)#恢复地址
                
            
            
            method_idx = 0
            print "virtual_methods_size",virtual_methods_size
            while(virtual_methods_size > 0):
                method_idx_diff = self.DecUnsignedLEB128(self.dex)
                access_flags = self.DecUnsignedLEB128(self.dex)
                code_off = self.DecUnsignedLEB128(self.dex)
                virtual_methods_size-=1
                savedaddr = self.dex.tell()#保存当前地址
                
                #取出field
                name_idx = self.method_table[method_idx + method_idx_diff][2]
                self.dex.seek(self.string_table[name_idx],0)
                strlen = self.DecUnsignedLEB128(self.dex)
                #用tell来获取当前位置
                methodoff = self.dex.tell()
                #混淆field
                #print "filed:",self.dex.read(strlen),"len:",strlen
                self.DoConfuse(methodoff,strlen)
                
                
                method_idx+=method_idx_diff
                
                
                self.dex.seek(savedaddr)#恢复地址
                
            
            
    
    #判断这个类是否能被混淆
    def ClassCanBeConfused(self,classstr,superclassstr):
        #if superclassstr == "":
        #    return True
        if classstr.find("$")!=-1: #不混淆内部类
            return False
        if classstr.find("Lcom/example/util/Signature")!=-1:
            return True
        
        return False
    
    
    def DoConfuse(self,addr,len):
        #print "addr",addr
        self.dex.seek(addr)
        str = self.GenRandomStr(len)
        self.dex.write(str)
    
    def GenRandomStr(self,len):
        
        while True:
            
            str = ""
            
            for i in range(len):
                num = random.randint(0,61)
                str = "".join([str,self.randomstr[num]])
            print str
            
            if self.usedstr.has_key(str): #防止重复
                continue
            else:
                self.usedstr[str] = 1
                break
        
        return str
        
    def ReCalSignature(self):
        #4 + 4 + 4 + 20
        self.dex.seek(32)
        sigdata = self.dex.read()
        sha1 = hashlib.sha1()
        sha1.update(sigdata)
        print "signature:",sha1.hexdigest(),"\n",sha1.digest()
        
        self.dex.seek(12)
        self.dex.write(struct.pack("20s",sha1.digest()))
        
    
    def ReCalChecksum(self):
        self.dex.seek(12)
        checkdata = self.dex.read()
        checksum = zlib.adler32(checkdata)
        print "checksum:",checksum
        
        self.dex.seek(8)
        self.dex.write(struct.pack("i",checksum))
    
    
    
    def DecUnsignedLEB128(self,file):
        result = struct.unpack("i", file.read(4))[0]
        result = result&0x000000ff  
        file.seek(-3, 1)  # 不能直接从1字节强转为4字节，所以先取4字节，再清空3字节
        if(result > 0x7f):
            next = struct.unpack("i", file.read(4))[0]
            next = next&0x000000ff
            file.seek(-3, 1)
            result = (result&0x7f) | (next&0x7f)<<7
            if(next > 0x7f):
                next = struct.unpack("i", file.read(4))[0]
                next = next&0x000000ff
                file.seek(-3, 1)
                result = result | (next&0x7f)<<14
                if(next > 0x7f):
                    next = struct.unpack("i", file.read(4))[0]
                    next = next&0x000000ff
                    file.seek(-3, 1)
                    result = result | (next&0x7f)<<21
                    if(next > 0x7f):
                        next = struct.unpack("i", file.read(4))[0]
                        next = next&0x000000ff
                        file.seek(-3, 1)
                        result = result | next<<28
                        
        #print "result:", result
        return result    
    
    
    def CloseDexFile(self):
        self.dex.close()
            



if __name__ == "__main__":
    df = DexFile("/home/cyg0810/crackdidiclasses.dex") 
    df.ReadDexHeader()
    #df.CalSignature()
    #df.CalChecksum()

    df.ReadStringTable()
   # print "len :",len(df.strings),df.strings
    df.ReadTypeTable()

    df.ReadFieldsTable()
    df.ReadMethodTable()
    #print "string table:",len(df.string_table),df.string_table
    #print "type table",len(df.type_table),df.type_table    
    #print "field table:",df.field_table
    #print "method table:",df.method_table
    
    #df.GenRandomStr(5)
    df.ConfuseClass()
    
    df.ReCalSignature()
    df.ReCalChecksum()    
    #df.ReadClass()
    df.CloseDexFile()
            