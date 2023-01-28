#!/usr/bin/python3

import argparse
import array
import binascii
import os

from enum import Enum, unique
from pathlib import Path
from glob import iglob

from parser import *

katdir = 'nist-kat'
outdir = "test-vectors"

@unique
class CipherTypes(Enum):
    cbc = 1
    gcm = 2
    sha256 = 3
    sha512 = 4

class GenTestCase:
    def __init__(self, fname, cipherType):
        self.mode = None
        self.cipherType = cipherType
        self.testStruct = None
        self.testData = None

        if cipherType == CipherTypes.cbc:
            self.columns = ['KEY', 'IV', 'PLAINTEXT', 'CIPHERTEXT']
            self.staticParameters = ['KEY', 'IV']
            self.dynamicParameters = ['PLAINTEXT', 'CIPHERTEXT']
            self.testStructName = "aes_cbc_test"
            self.testFileNames = [os.path.join(katdir, 'KAT_AES', 'CBC*.rsp')]
            self.testFileNames += [os.path.join(katdir, 'MMT_AES', 'CBC*.rsp')]
        elif cipherType == CipherTypes.gcm:
            self.columns = ['Key', 'IV', 'CT', 'AAD', 'Tag', 'PT']
            self.staticParameters = ['Key']
            self.dynamicParameters = ['IV', 'CT', 'AAD', 'Tag', 'PT']
            self.testStructName = "aes_gcm_test"
            self.testFileNames = [os.path.join(katdir, 'gcmtestvectors', 'gcm*128.rsp')]
            self.testFileNames += [os.path.join(katdir, 'gcmtestvectors', 'gcm*256.rsp')]
        elif cipherType == CipherTypes.sha256:
            self.columns = ['Msg', 'MD']
            self.staticParameters = ['MD']
            self.dynamicParameters = ['Msg']
            self.testStructName = "sha256_test"
            self.testFileNames = [os.path.join(katdir, "shabytetestvectors", "SHA256*.rsp")]
        elif cipherType == CipherTypes.sha512:
            self.columns = ['Msg', 'MD']
            self.staticParameters = ['MD']
            self.dynamicParameters = ['Msg']
            self.testStructName = "sha512_test"
            self.testFileNames = [os.path.join(katdir, "shabytetestvectors", "SHA512*.rsp")]
        else:
            raise ValueError("Unsupported cipher type: " + cipherType)

        self.headerFile = open(os.path.join(outdir, fname), "w")
        fname = Path(fname).stem
        fname = fname.upper()
        fname = fname.replace("-", "_")
        self.headerFile.write("#ifndef _" + fname + "\n")
        self.headerFile.write("#define _" + fname + "\n\n")

    def __del__(self):
        self.headerFile.write("\n#endif\n")
        self.headerFile.close()

    def parseKeyLen(self, fname):
        if fname.find("128") != -1:
            return 128
        elif fname.find("192") != -1:
            return 192
        elif fname.find("256") != -1:
            return 256
        else:
            raise ValueError("Unknown key length")

    def parseTestMode(self, fname):
        if fname.find("Encrypt") != -1:
            self.mode = 'ENCRYPT'
        elif fname.find("Decrypt") != -1:
            self.mode = 'DECRYPT'
        else:
            raise ValueError("Unknown test mode, fname: " + fname)

    def usesKey(self):
        if (self.cipherType == CipherTypes.cbc or
            self.cipherType == CipherTypes.gcm):
            return True
        return False

    def genTests(self):
        for path in self.testFileNames:
            for fname in iglob(path):
                testName = Path(fname).stem
                self.headerFile.write("#include \"" + testName + ".h" + "\"\n")

        self.headerFile.write("\nstatic const struct " + self.testStructName + "_suite")
        self.headerFile.write(" " + self.cipherType.name + "_suites[] = {\n")

        for path in self.testFileNames:
            for fname in iglob(path):
                testName = Path(fname).stem

                # AES-GCM test vectors have test mode(encrypt/decrypt) encoded in
                # the file name, instead of storing it in the file itself...
                if self.cipherType == CipherTypes.gcm:
                    self.parseTestMode(fname)

                with KATParser(fname, self.columns) as parser:
                    count = self.parseTestFile(parser, testName)

                self.headerFile.write("    {.name = \"" + testName + "\", ")
                self.headerFile.write(".count = " + str(count) + ", ")
                if (self.usesKey()):
                    keylen = self.parseKeyLen(testName)
                    self.headerFile.write(".keylen = " + str(keylen) + ", ")
                self.headerFile.write(".tests = " + testName + "},\n")

        self.headerFile.write("};")

    def writeStaticParameter(self, name, data):
        data = binascii.unhexlify(data)
        data = array.array('B', data)

        self.testStruct.append("    ." + name + " = {")
        for byte in data[:-1]:
            self.testStruct.append(hex(byte) + ",")
        self.testStruct.append(hex(data[-1]) + "},\n")

    def writeDynamicParameter(self, testCaseName, name, data):
        data = binascii.unhexlify(data)
        data = array.array('B', data)
        arrayName = testCaseName + name.capitalize()

        self.testData.append("__attribute__((aligned(16)))\n")
        self.testData.append("static const uint8_t " + arrayName + "[] = {")
        for byte in data[:-1]:
            self.testData.append(hex(byte) + ",")
        self.testData.append(hex(data[-1]) + "};\n\n")

        self.testStruct.append("    ." + name + " = ")
        self.testStruct.append(arrayName + ",\n")
        if (name != "ciphertext" and name != "pt"):
            self.testStruct.append("    ." + name + "len" + " = " + str(len(data)) + ",\n")

    def writeTestParameters(self, mode):
        if self.cipherType == CipherTypes.sha256 or self.cipherType == CipherTypes.sha512:
               return

        if mode == 'ENCRYPT':
            self.testStruct.append("    .encrypt = true,\n")
        else:
            self.testStruct.append("    .encrypt = false,\n")

        if self.cipherType == CipherTypes.gcm:
            if 'FAIL' in data.keys():
                self.testStruct.append("    .expect_fail = true\n")
            else:
                self.testStruct.append("    .expect_fail = false\n")


    def writeTestFile(self, testName):
        fp = open(os.path.join(outdir, testName + ".h"), "w")
        for data in self.testData:
            fp.write(data)
        for data in self.testStruct:
            fp.write(data)
        fp.close()

    def parseTestFile(self, parser, testName):
        count = 0
        self.testData = []
        self.testStruct = []

        self.testStruct.append("static const struct " + self.testStructName)
        self.testStruct.append(" " + testName + "[] = {\n")

        for mode, lines in next(parser):
            if self.mode:
                mode = self.mode

            for data in lines:
                testCaseName = testName + str(count)
                self.testStruct.append("{\n")

                for parameter in self.staticParameters:
                    if data[parameter]:
                        self.writeStaticParameter(parameter.lower(), data[parameter])

                for parameter in self.dynamicParameters:
                    if data[parameter]:
                        self.writeDynamicParameter(testCaseName, parameter.lower(), data[parameter])

                self.writeTestParameters(mode)

                if self.cipherType == CipherTypes.gcm:
                    if 'FAIL' in data.keys():
                        self.testStruct.append("    .expect_fail = true\n")
                    else:
                        self.testStruct.append("    .expect_fail = false\n")


                count = count + 1
                self.testStruct.append("},\n")

        self.testStruct.append("};")

        self.writeTestFile(testName)
        return count

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate C headers from NIST test vectors')
    parser.add_argument('algorithm', nargs='+')

    args = parser.parse_args()
    args = vars(args)
    values = args['algorithm']

    if not os.path.exists(outdir):
        os.mkdir(outdir)

    for val in values:
        if val == 'cbc':
            print("Generating AES-CBC test vectors")
            gen = GenTestCase("aes-cbc-vectors.h", CipherTypes.cbc)
            gen.genTests()
        if val == 'gcm':
            print("Generating AES-GCM test vectors")
            gen = GenTestCase("aes-gcm-vectors.h", CipherTypes.gcm)
            gen.genTests()
        if val == 'sha256':
            print("Generating SHA256 test vectors")
            gen = GenTestCase("sha256-vectors.h", CipherTypes.sha256)
            gen.genTests()
        if val == 'sha512':
            print("Generating SHA256 test vectors")
            gen = GenTestCase("sha512-vectors.h", CipherTypes.sha512)
            gen.genTests()
