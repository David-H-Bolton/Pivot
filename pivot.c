// pivot.c C99 Author, D. Bolton 2020. dhbolton.com

#include <stdio.h>
#include <stdlib.h>   // Must be included for malloc to work correctly
#include <sys/stat.h>
#include <ctype.h>
#include <io.h>
#include <share.h>
#include <string.h>
#include "sodium.h"
#include <fcntl.h>
#include <time.h>

// This encryption works by taking 84 bytes at a time
// 01 02 ... 63
// Then 


#define NUMSTREAMS 64
// typedefs
typedef char key[NUMSTREAMS];

// Parameter variables
int isEncrypt;  // 1 = Encrypt
int isDecrypt;  // 1 = Decrypt
int generateKeyFile; // only true if -g
char* infile;
char* keyfile;
char* outfile;
char buff[20];
key _key;
//char* streams[NUMSTREAMS];
uint64_t rngstate[4]; 
char bits[8] = { 128,64,32,16,8,4,2,1 };
clock_t startTime, endTime;
int fdi, fdo;
long blockCount;


int CheckParameters(int argc, char* argv[]);
void CreateKeyfile();
void DoEncrypt();
void DoDecrypt();
int WriteKeyfile();
int LoadKeyfile();
int FileExists(const char* filename);
void error(char* errormsg, char* errorstr);
void hint();
void assignfile(char* parm);
void AllocStreams(long filesize);
void FreeStreams();
void ShowParameters();
char * inttoa(int i);
void ExitFunction(void);
off_t filesize(const char* filename);
void ReplaceExtension(char* s, char* extension);
// Simple time calc
double TimeSpent();


int main(int argc, char* argv[]) {
    int atv = atexit(ExitFunction);
    int i = sodium_init();
    if (i<0 ) {
        error("Unable to initialise sodium library. Error = ",inttoa(i) );
    }
    CheckParameters(argc, argv);
    ShowParameters();
    if (generateKeyFile) {
        CreateKeyfile();
        if (WriteKeyfile()) {
            error("Unable to write to", keyfile);
        }
    }
    if (isEncrypt) {
        DoEncrypt();
    }
    else 
    if (isDecrypt){
        DoDecrypt();
    }
}

// from http://prng.di.unimi.it/xoshiro256plusplus.c
static inline uint64_t rotl(const uint64_t x, int k) {
    return (x << k) | (x >> (64 - k));
}

// Returns a Uint64 random number
uint64_t next(void) {
    const uint64_t result = rotl(rngstate[0] + rngstate[3], 23) + rngstate[0];
    const uint64_t t = rngstate[1] << 17;
    rngstate[2] ^= rngstate[0];
    rngstate[3] ^= rngstate[1];
    rngstate[1] ^= rngstate[2];
    rngstate[0] ^= rngstate[3];
    rngstate[2] ^= t;
    rngstate[3] = rotl(rngstate[3], 45);
    return result;
}

// use key to init the rng
void InitXorByte() {
    memcpy(rngstate, _key, sizeof(rngstate)); 
}

// return a random char with 4 or more set bits- used to xor values to obscure them
char RandomChar(){
    int bits;
    char c;
    do {
        c = next() & 0xff;
        bits = (c * 01001001001ULL & 042104210421ULL) % 017; // counts bits in c- see https://stackoverflow.com/questions/697978/c-code-to-count-the-number-of-1-bits-in-an-unsigned-char
    } while (bits < 4);
    return c;
}

// Does the actual encryption
void DoEncrypt() {      
    unsigned char data[NUMSTREAMS],dataout[NUMSTREAMS];  
    startTime = clock();
    long fsize = (long)filesize(infile);
    size_t bytes_read, bytes_expected = NUMSTREAMS;
    if (!generateKeyFile) {
        if (!LoadKeyfile()) {
            error("Unable to load key file:", keyfile);
        }
    }
    InitXorByte();
    int errnum = _sopen_s(&fdi, infile, O_RDONLY | O_BINARY, _SH_DENYWR, _S_IREAD);
    if (errnum != 0)
        error("Error reading file - error number", inttoa(errnum));    
    errnum = _sopen_s(&fdo, outfile, O_CREAT | O_WRONLY | O_BINARY | O_TRUNC, _SH_DENYWR, _S_IWRITE);
    if (errnum != 0)
        error("Error writing file - error number", inttoa(errnum));
    
    blockCount = 0;
    do {
        memset(data, 0, sizeof(data));
        memset(dataout, 0, sizeof(dataout));
        bytes_read = _read(fdi, data, bytes_expected);
        // Obscure by xor with 
        for (int i = 0; i < NUMSTREAMS; i++) {
            data[i] ^= RandomChar();
        }    

        int bit = 128;
        for (int bi = 0; bi < 8; bi++) {
            for (int b = 0; b < NUMSTREAMS; b++) {
                dataout[b] = (dataout[b] >> 1) | (data[b] & bit);
                data[b] <<= 1;
            }
        }
             
        // Now alter the order of bytes according to the key
        for (int i = 0; i < NUMSTREAMS; i++) {
           data[i] = dataout[_key[i]];
        }

        _write(fdo, data, NUMSTREAMS); 
        blockCount++;
    } while (!_eof(fdi));    
    _close(fdi);
    _close(fdo);
    endTime = clock();
    printf("Processed %lu KB in %6.3f seconds\n ", (blockCount * NUMSTREAMS)/1024, TimeSpent());
}

// Now Decrypt
void DoDecrypt() {    
    startTime = clock();
    long fsize = (long)filesize(infile);
    long numRows = fsize / NUMSTREAMS;
    blockCount = 0;

    if (!LoadKeyfile()) {
        error("Unable to load key file:", keyfile);
    }

    int fdi, fdo,errnum,numRead;
    unsigned char datain[NUMSTREAMS],data[NUMSTREAMS];

    InitXorByte();
    errnum = _sopen_s(&fdi, infile, O_RDONLY | O_BINARY, _SH_DENYWR, _S_IREAD);
    if (errnum != 0)
        error("Error reading file - error number", inttoa(errnum));
    errnum = _sopen_s(&fdo, outfile, O_CREAT | O_WRONLY | O_BINARY | O_TRUNC, _SH_DENYWR, _S_IWRITE);
    if (errnum != 0)
        error("Error writing file - error number", inttoa(errnum));
    for (long strindex = 0; strindex < numRows; strindex++) {
        memset(data, 0, sizeof(data));
        numRead= _read(fdi, datain, NUMSTREAMS);        
 
    // reorder bytes according to key
    for (int i = 0; i < NUMSTREAMS; i++) {
         data[_key[i]] = datain[i] ;
    }

    // -----decrypt
        int bit = 1;
        memset(datain, 0, sizeof(data));
        for (int bi = 0; bi < 8; bi++) {
            for (int b = 0; b < NUMSTREAMS; b++) {
                datain[b] = (datain[b] << 1) | (data[b] & bit);
                data[b] >>= 1;
            }
        }
    
       // deobfuscate data
        for (int i = 0; i < NUMSTREAMS; i++) {
           datain[i] ^= RandomChar();
        }        
        _write(fdo, datain, NUMSTREAMS);
        blockCount++;
    }
    _close(fdi);
    _close(fdo);
    endTime = clock();
    printf("Processed %lu KB in %6.3f second(s)\n ", (blockCount * NUMSTREAMS)/1024, TimeSpent());
}

void ExitFunction(void) {
// Duymmy for now
}

void CreateKeyfile() {
    uint32_t ival;
    int i,index1,index2;
    for (i = 0; i < NUMSTREAMS; i++) {
        _key[i] = i;
    }
    for (i = 0; i < 1000; i++) {
        do {
            index1 = randombytes_uniform(NUMSTREAMS);
            index2 = randombytes_uniform(NUMSTREAMS);
        } while (index1 == index2);
        ival = _key[index2]; // swap two indices
        _key[index2] = _key[index1];
        _key[index1] = ival;
    }
    return;
 }

int LoadKeyfile() {
    FILE* read_ptr;
    int err = fopen_s(&read_ptr, keyfile, "rb");
    int numRead = fread(_key, sizeof(_key), 1, read_ptr);
    fclose(read_ptr);
    return numRead;
}

int WriteKeyfile() {
    FILE* write_ptr;
    int err = fopen_s(&write_ptr, keyfile, "wb"); 
    fwrite(_key, sizeof(_key), 1, write_ptr);
    fclose(write_ptr);
    return err;
}

char* inttoa(int i) {
    sprintf_s(buff, sizeof(buff), "%d", i);
    return buff;
}

// parses parameters into variables and checks parameters are valid 
int CheckParameters(int argc, char* argv[]) {
    if (argc < 1 || argc >6) {
        error("too few or too many parameters", "");
        hint();
        exit(1);
    }
    //return 0;
    isEncrypt = 0;
    isDecrypt = 0;
    generateKeyFile=0;
    infile = NULL;
    outfile = NULL;
    keyfile = NULL;

    for (int pindex = 1; pindex < argc; pindex++) {
        char* parm = argv[pindex];
        if (strcmp(parm, "/?")==0 || strcmp(parm,"-h")==0 || strcmp(parm,"-help")==0) {
            hint();
            exit(1);
        }
        if (parm[0] == '-') {
            if (strlen(parm) <2) {
                error("Missing option ", parm);
            }
            char opt = tolower(parm[1]);
            switch (opt) {
            case 'd':
                isDecrypt = 1;
                break;
            case 'e':
                    isEncrypt = 1;
                    break;
                case 'g':
                    generateKeyFile = 1;
                    break;
                default:
                {
                    error("Unknown option", parm);
                }
            }
        }            
        else {
                assignfile(parm);
             }
    }

    // Now error check all possible cases
    if (isEncrypt && isDecrypt) {
        error("Cannot do both encrypt and decrypt at the same time", "");
    }
    if (isDecrypt && generateKeyFile) {
        error("Cannot generate a key file and decrypt simultaneously","");
    }
    if (infile == NULL && (!generateKeyFile)) { // no infile and not generating a keyfile. That's a no no!
        error("No infile supplied","");
    }

    if ((generateKeyFile || isEncrypt || isDecrypt) && (keyfile == NULL)) {
        if (infile == NULL) {
            error("No filename provided for keyfile", "");
        }
        // Get keyfile nme from infile
        keyfile = malloc(strlen(infile) + 5); // Alloc memory for outfile plus a few spare in case extension is longer
        strncpy_s(keyfile, strlen(infile) + 1, infile, strlen(infile) + 1);
        ReplaceExtension(keyfile, ".key");
        if (!isDecrypt && !isEncrypt) { // Only generating a key, clear infile so can pass later checks
            infile = NULL;
        }
    }

    if (infile && !outfile) {                 // Input file provided but not output so use input with .pvt extension for output
        outfile = malloc(strlen(infile) + 5); // Alloc memory for outfile plus a few spare in case extension is longer
        strncpy_s(outfile,strlen(infile)+1, infile, strlen(infile) + 1);
        if (isEncrypt) {
            ReplaceExtension(outfile, ".pvt");
        }
        else
            if (isDecrypt) {
                ReplaceExtension(outfile, ".bin");
            }
            else
                error("Should never get to here!", "");
    }
    if (!generateKeyFile) { // not genberating keyfile, so 
        if (keyfile == NULL) {  // no keyfile specified so create from infile
            keyfile = malloc(strlen(infile) + 5); // Alloc memory for outfile plus a few spare in case extension is longer
            strncpy_s(keyfile, strlen(infile) + 1, infile, strlen(infile) + 1);
        }
        if (!FileExists(keyfile)) { // Error if keyfile doesn't exist
            error("Missing keyfile:", keyfile);
        }
    }
    return 0;
}

void ShowParameters() {    
    if (generateKeyFile) {
        printf("Generated keyfile in %s. ", keyfile);
    }

    if (isEncrypt)
        printf("Encrypt ");
    if (isDecrypt)
        printf("Decrypt ");
    if (infile && outfile)
    {
        printf(infile);
        printf(" to %s", outfile);
        if (keyfile != NULL) {
            printf(" using keyfile:%s", keyfile);
        }
    }
    printf("\n");
}

// assign files in order infile, outfile, keyfile
void assignfile(char* parm) {
    if (infile == NULL) {
        infile = parm;
        if (!FileExists(infile) && generateKeyFile==0) {
            error("Cannot find file:", infile);
        }
    }
    else
        if (outfile == NULL) {
            outfile = parm;
        }
        else
            if (keyfile == NULL) {
                keyfile = parm;
            }
            else
                error("Unknown type file:", parm);
}

// Show help hints
void hint() {
    printf("Pivot Encryption/decryption by D. Bolton 2020. V1.000 (%d-streams)\n",NUMSTREAMS);
    printf("==================================================================\n");
    printf("Usage:\n");
    printf("pivot -options file1 file2 [ keyfile]\n");
    printf("Where options are either\n");
    printf("   -e = encrypt file 1 into file2 using keyfile\n");
    printf("   -d = decrypt file 1 into file2 using keyfile\n");
    printf("   -g = generate keyfile, creates key file or file1.key if keyfile name not supplied\n");
    printf("Examples\n");
    printf("pivot -e -g myfile.txt myfile.out myfile.key - encrypts myfile.txt into myfile.out using myfile.key\n");
    printf("pivot -e -g myfile.txt   - encrypts myfile.txt into myfile.pvt using generated keyfile myfile.key\n");
    printf("pivot -g afile.xyz       - generates keyfile.xyz\n");
}


// Get file size - from https://stackoverflow.com/questions/8236/how-do-you-determine-the-size-of-a-file-in-c
off_t filesize(const char* filename) {
    struct stat st;

    if (stat(filename, &st) == 0)
        return st.st_size;

    return -1;
}

// output error and halt program
void error(char* errormsg, char* errorstr) {
    printf("Error: %s %s\n\n", errormsg, errorstr);
    exit(1);
}

// Check file exists, returns 1 if it does, 0 otherwise 
int FileExists(const char* filename) {
    struct stat buffer;
    return 1 + stat(filename, &buffer); // stat return 0 if it exists, -1 if not
}

// change file extensions
void ReplaceExtension(char* s, char* extension) {
    int i = 0;
    while ((s[i] != '.') && (s[i] != '\0'))
        i++;
    if (s[i] == '.')
        strncpy_s(s + i, strlen(extension) + 1, extension, strlen(extension) + 1);
    else
        strcat_s(s, strlen(extension), extension);
}

// Simple time calc
double TimeSpent() {
    return (endTime - startTime) / CLOCKS_PER_SEC;
}