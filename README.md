# Pivot
Pivot provides lightweight encryption for files. 

A key of 64 bytes with unique values 0-63 is generated and randomly shuffled by use of a cryptographic random number generator (it uses libsodium https://github.com/jedisct1/libsodium for this). There are 64! = 1.2688693e+89 possible keys.

The pivot algorithm reads in blocks of sizty-four bytes at a time. These are then xored with a stream of randomly generated bytes with the property that each byte has 5-8 bits set. This is just an obscuring stage, it is not the encryption algorithm. This obscuring rng uses xorshiro256++ http://prng.di.unimi.it/xoshiro256plus.c and is seeded by bytes from the key. 

The encryption is this: the 64 bytes are sliced into 64 bit streams. Stream 0 takes bit 7 of the byte 0, then bit 7 of the byte 8 and so on. Stream 1 takes bit 6 of the byte 1, bit 6 of byte 9. 

The 64 bytes thus formed are now shuffled (i.e. indexed) according to the key and the shuffled bytes written to file.

Decryption is the reverse, provided the key is available. 

As there are 1.2688693e+89 possible keys, brute forcing this may take rather a while.  

Compiling
There is just one file pivot.c.

Running it.
A copy of libsodium.dll should be obtained/built from source and included in the same folder as pivot.exe.

Usage:
pivot /? will show these.

pivot -options file1 file2 [ keyfile]
Where options are either
   -e = encrypt file 1 into file2 using keyfile
   -d = decrypt file 1 into file2 using keyfile
   -g = generate keyfile, creates key file or file1.key if keyfile name not supplied
Examples
pivot -e -g myfile.txt myfile.out myfile.key - encrypts myfile.txt into myfile.out using myfile.key
pivot -e -g myfile.txt   - encrypts myfile.txt into myfile.pvt using generated keyfile myfile.key
pivot -g afile.xyz       - generates keyfile.xyz

Known Issues
1. The decrypted file has some extra 0s bytes on the end due to blocking. Files that are not a multiple of 8 bytes in length will get rounded up to a multiple of 8. This will be fixed.
2. This was developed on Windows. A Linux version (the only difference is the Windows file open functions called). A Linux version will be fortthcoming. 

Copyright 2020 David H Bolton

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
