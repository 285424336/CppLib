#ifndef ALGORITHM_HELPER_H_INCLUDED
#define ALGORITHM_HELPER_H_INCLUDED

#include <mutex>
#include <algorithm>
#if defined(_MSC_VER)
#include <windows.h>
#include <windef.h>
#include <wincrypt.h>
#elif defined(__GNUC__)
#include <unistd.h>
#include <sys/time.h>
#include <fcntl.h>
#else
#error unsupported compiler
#endif

#define	CKSUM_CARRY(x) (x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))

class AlgorithmHelper
{
private:
    /* data for our random state */
    typedef struct NrandHandle {
        unsigned char    i;
        unsigned char    j;
        unsigned char    s[256];
        unsigned char    *tmp;
        int   tmplen;
    }NrandHandle_t;

public:
    /**
    *calcuate the bit count in the char
    */
    static int BitCount(unsigned char n)
    {
        unsigned char tmp = n - ((n >> 1) & 0X77) - ((n >> 2) & 0X33) - ((n >> 3) & 0X11);
        return (tmp % 15);
    }
    /**
    *calcuate the bit count in the short
    */
    static int BitCount(unsigned short n)
    {
        unsigned short tmp = n - ((n >> 1) & 0XB6DB) - ((n >> 2) & 0X9249);
        return ((tmp + (tmp >> 3)) & 0X71C7) % 63;
    }
    /**
    *calcuate the bit count in the int
    */
    static int BitCount(unsigned int n)
    {
        unsigned int tmp = n - ((n >> 1) & 033333333333) - ((n >> 2) & 011111111111);
        return ((tmp + (tmp >> 3)) & 030707070707) % 63;
    }
    /**
    *calcuate the bit count in the long long
    */
    static int BitCount(unsigned long long n)
    {
        unsigned long long tmp = n - ((n >> 1) & 0X7777777777777777) - ((n >> 2) & 0X3333333333333333) - ((n >> 3) & 0X1111111111111111);
        return ((tmp + (tmp >> 4)) & 0X0F0F0F0F0F0F0F0F) % 255;
    }
    /**
    *reverse the bit sequence in the char, for example 11101101 to 10110111
    */
    static unsigned char BitReverse(unsigned char n)
    {
        n = ((n >> 1) & 0x55) | ((n << 1) & 0xaa);
        n = ((n >> 2) & 0x33) | ((n << 2) & 0xcc);
        return (n >> 4) | (n << 4);
    }
    /**
    *reverse the bit sequence in the short, for example 11101101 to 10110111
    */
    static unsigned short BitReverse(unsigned short n)
    {
        n = ((n >> 1) & 0x5555) | ((n << 1) & 0xaaaa);
        n = ((n >> 2) & 0x3333) | ((n << 2) & 0xcccc);
        n = ((n >> 4) & 0x0f0f) | ((n << 4) & 0xf0f0);
        return (n >> 8) | (n << 8);
    }
    /**
    *reverse the bit sequence in the int, for example 11101101 to 10110111
    */
    static unsigned int BitReverse(unsigned int n)
    {
        n = ((n >> 1) & 0x55555555) | ((n << 1) & 0xaaaaaaaa);
        n = ((n >> 2) & 0x33333333) | ((n << 2) & 0xcccccccc);
        n = ((n >> 4) & 0x0f0f0f0f) | ((n << 4) & 0xf0f0f0f0);
        n = ((n >> 8) & 0x00ff00ff) | ((n << 8) & 0xff00ff00);
        return (n >> 16) | (n << 16);
    }
    /**
    *reverse the bit sequence in the long long, for example 11101101 to 10110111
    */
    static unsigned long long BitReverse(unsigned long long n)
    {
        n = ((n >> 1) & 0x5555555555555555) | ((n << 1) & 0xaaaaaaaaaaaaaaaa);
        n = ((n >> 2) & 0x3333333333333333) | ((n << 2) & 0xcccccccccccccccc);
        n = ((n >> 4) & 0x0f0f0f0f0f0f0f0f) | ((n << 4) & 0xf0f0f0f0f0f0f0f0);
        n = ((n >> 8) & 0x00ff00ff00ff00ff) | ((n << 8) & 0xff00ff00ff00ff00);
        n = ((n >> 16) & 0x0000ffff0000ffff) | ((n << 16) & 0xffff0000ffff0000);
        return (n >> 32) | (n << 32);
    }

    /**
    *get the check sum of the buf
    *buf(in): the buf need to calcaute
    *size(in): buf size of byte
    */
    static unsigned short CheckSum(const unsigned char *buffer, register unsigned long size)
    {
        register unsigned long cksum = 0;
        register const unsigned short *p = (unsigned short *)buffer;
        bool is_singular = size & 1;
        size = size >> 1;
        while (size--) cksum += *p++;
        if (is_singular) cksum += *(unsigned char*)p;
        cksum = (cksum >> 16) + (cksum & 0xffff);
        cksum += (cksum >> 16);
        return (unsigned short)(~cksum);
    }

    /**
    *get the check sum of the buf, after you add the last buf, you should use CKSUM_CARRY you get the check sum result
    *buf(in): the buf need to calcaute add
    *size(in): buf size of byte
    *cksum(in): check sum of pre
    */
    static unsigned int CheckSumAdd(const unsigned char *buffer, register unsigned long size, register int cksum)
    {
        register const unsigned short *p = (unsigned short *)buffer;
        bool is_singular = size & 1;
        size = size >> 1;
        while (size--) cksum += *p++;
        if (is_singular) cksum += *(unsigned char*)p;
        return cksum;
    }

    /**
    *get a list of random bytes
    *buf(out): random bytes buf
    *numbytes(in): buf len
    */
    static void GetRandomBytes(void *buf, int numbytes) 
    {
        static NrandHandle_t state;
        static int state_init = 0;
        static std::mutex init_lock;

        if (buf == NULL || numbytes == 0) {
            return;
        }

        /* Initialize if we need to */
        {
            std::unique_lock<std::mutex> lock(init_lock);
            if (!state_init) {
                state_init = 1;
                NrandInit(&state);
            }
        }
        /* Now fill our buffer */
        NrandGet(&state, buf, numbytes);
    }

    /**
    *get random 64 bit number
    *return random number
    */
    static unsigned long long GetRandomU64() 
    {
        unsigned long long i;
        GetRandomBytes(&i, sizeof(i));
        return i;
    }

    /**
    *get random 32 bit number
    *return random number
    */
    static unsigned int GetRandomU32()
    {
        unsigned int i;
        GetRandomBytes(&i, sizeof(i));
        return i;
    }

    /**
    *get random 16 bit number
    *return random number
    */
    static unsigned short GetRandomU16()
    {
        unsigned short i;
        GetRandomBytes(&i, sizeof(i));
        return i;
    }

    /**
    *get random 8 bit number
    *return random number
    */
    static unsigned char GetRandomU8()
    {
        unsigned char i;
        GetRandomBytes(&i, sizeof(i));
        return i;
    }

    /**
    *get random 32 bit number, this number will never equal to before in running time
    *return random number
    */
    static unsigned int GetRandomUniqueU32()
    {
        static unsigned int state, tweak1, tweak2, tweak3;
        static int state_init = 0;
        unsigned int output;

        /* Initialize if we need to */
        if (!state_init) {
            GetRandomBytes(&state, sizeof(state));
            GetRandomBytes(&tweak1, sizeof(tweak1));
            GetRandomBytes(&tweak2, sizeof(tweak2));
            GetRandomBytes(&tweak3, sizeof(tweak3));

            state_init = 1;
        }

        /* What is this math crap?
        *
        * The whole idea behind this generator is that an LCG can be constructed
        * with a period of exactly 2^32.  As long as the LCG is fed back onto
        * itself the period will be 2^32.  The tweak after the LCG is just
        * a good permutation in GF(2^32).
        *
        * To accomplish the tweak the notion of rounds and round keys from
        * block ciphers has been borrowed.  The only special aspect of this
        * block cipher is that the first round short-circuits the LCG.
        *
        * This block cipher uses three rounds.  Each round is as follows:
        *
        * 1) Affine transform in GF(2^32)
        * 2) Rotate left by round constant
        * 3) XOR with round key
        *
        * For round one the affine transform is used as an LCG.
        */

        /* Reasoning:
        *
        * Affine transforms were chosen both to make a LCG and also
        * to try to introduce non-linearity.
        *
        * The rotate up each round was borrowed from SHA-1 and was introduced
        * to help obscure the obvious short cycles when you truncate an LCG with
        * a power-of-two period like the one used.
        *
        * The XOR with the round key was borrowed from several different
        * published functions (but see Xorshift)
        * and provides a different sequence for the full LCG.
        * There are 3 32 bit round keys.  This generator can
        * generate 2^96 different sequences of period 2^32.
        *
        * This generator was tested with Dieharder.  It did not fail any test.
        */

        /* See:
        *
        * http://en.wikipedia.org/wiki/Galois_field
        * http://en.wikipedia.org/wiki/Affine_cipher
        * http://en.wikipedia.org/wiki/Linear_congruential_generator
        * http://en.wikipedia.org/wiki/Xorshift
        * http://en.wikipedia.org/wiki/Sha-1
        *
        * http://seclists.org/nmap-dev/2009/q3/0695.html
        */


        /* First off, we need to evolve the state with our LCG
        * We'll use the LCG from Numerical Recipes (m=2^32,
        * a=1664525, c=1013904223).  All by itself this generator
        * pretty bad.  We're going to try to fix that without causing
        * duplicates.
        */
        state = (((state * 1664525) & 0xFFFFFFFF) + 1013904223) & 0xFFFFFFFF;

        output = state;

        /* With a normal LCG, we would just output the state.
        * In this case, though, we are going to try to destroy the
        * linear correlation between IPs by approximating a random permutation
        * in GF(2^32) (collision-free)
        */

        /* Then rotate and XOR */
        output = ((output << 7) | (output >> (32 - 7)));
        output = output ^ tweak1; /* This is the round key */

                                  /* End round 1, start round 2 */

                                  /* Then put it through an affine transform (glibc constants) */
        output = (((output * 1103515245) & 0xFFFFFFFF) + 12345) & 0xFFFFFFFF;

        /* Then rotate and XOR some more */
        output = ((output << 15) | (output >> (32 - 15)));
        output = output ^ tweak2;

        /* End round 2, start round 3 */

        /* Then put it through another affine transform (Quick C/C++ constants) */
        output = (((output * 214013) & 0xFFFFFFFF) + 2531011) & 0xFFFFFFFF;

        /* Then rotate and XOR some more */
        output = ((output << 5) | (output >> (32 - 5)));
        output = output ^ tweak3;

        return output;
    }

    /**
    *calculate the CRC32 of bytes
    *buf(in): bytes
    *len(in): bytes len
    *return the CRC32 of the bytes buf[0..len-1]. 
    */
    static unsigned long CRC32(const unsigned char *buf, int len)
    {
        return UpdateCRC(0L, buf, len);
    }

    /**
    *calculate the CRC32C of bytes
    *buf(in): bytes
    *len(in): bytes len
    *return the CRC32C of the bytes buf[0..len-1].
    */
    static unsigned long CRC32C(const unsigned char *buf, int len)
    {
        static unsigned long crc_c[256] = {
            0x00000000L, 0xF26B8303L, 0xE13B70F7L, 0x1350F3F4L,
            0xC79A971FL, 0x35F1141CL, 0x26A1E7E8L, 0xD4CA64EBL,
            0x8AD958CFL, 0x78B2DBCCL, 0x6BE22838L, 0x9989AB3BL,
            0x4D43CFD0L, 0xBF284CD3L, 0xAC78BF27L, 0x5E133C24L,
            0x105EC76FL, 0xE235446CL, 0xF165B798L, 0x030E349BL,
            0xD7C45070L, 0x25AFD373L, 0x36FF2087L, 0xC494A384L,
            0x9A879FA0L, 0x68EC1CA3L, 0x7BBCEF57L, 0x89D76C54L,
            0x5D1D08BFL, 0xAF768BBCL, 0xBC267848L, 0x4E4DFB4BL,
            0x20BD8EDEL, 0xD2D60DDDL, 0xC186FE29L, 0x33ED7D2AL,
            0xE72719C1L, 0x154C9AC2L, 0x061C6936L, 0xF477EA35L,
            0xAA64D611L, 0x580F5512L, 0x4B5FA6E6L, 0xB93425E5L,
            0x6DFE410EL, 0x9F95C20DL, 0x8CC531F9L, 0x7EAEB2FAL,
            0x30E349B1L, 0xC288CAB2L, 0xD1D83946L, 0x23B3BA45L,
            0xF779DEAEL, 0x05125DADL, 0x1642AE59L, 0xE4292D5AL,
            0xBA3A117EL, 0x4851927DL, 0x5B016189L, 0xA96AE28AL,
            0x7DA08661L, 0x8FCB0562L, 0x9C9BF696L, 0x6EF07595L,
            0x417B1DBCL, 0xB3109EBFL, 0xA0406D4BL, 0x522BEE48L,
            0x86E18AA3L, 0x748A09A0L, 0x67DAFA54L, 0x95B17957L,
            0xCBA24573L, 0x39C9C670L, 0x2A993584L, 0xD8F2B687L,
            0x0C38D26CL, 0xFE53516FL, 0xED03A29BL, 0x1F682198L,
            0x5125DAD3L, 0xA34E59D0L, 0xB01EAA24L, 0x42752927L,
            0x96BF4DCCL, 0x64D4CECFL, 0x77843D3BL, 0x85EFBE38L,
            0xDBFC821CL, 0x2997011FL, 0x3AC7F2EBL, 0xC8AC71E8L,
            0x1C661503L, 0xEE0D9600L, 0xFD5D65F4L, 0x0F36E6F7L,
            0x61C69362L, 0x93AD1061L, 0x80FDE395L, 0x72966096L,
            0xA65C047DL, 0x5437877EL, 0x4767748AL, 0xB50CF789L,
            0xEB1FCBADL, 0x197448AEL, 0x0A24BB5AL, 0xF84F3859L,
            0x2C855CB2L, 0xDEEEDFB1L, 0xCDBE2C45L, 0x3FD5AF46L,
            0x7198540DL, 0x83F3D70EL, 0x90A324FAL, 0x62C8A7F9L,
            0xB602C312L, 0x44694011L, 0x5739B3E5L, 0xA55230E6L,
            0xFB410CC2L, 0x092A8FC1L, 0x1A7A7C35L, 0xE811FF36L,
            0x3CDB9BDDL, 0xCEB018DEL, 0xDDE0EB2AL, 0x2F8B6829L,
            0x82F63B78L, 0x709DB87BL, 0x63CD4B8FL, 0x91A6C88CL,
            0x456CAC67L, 0xB7072F64L, 0xA457DC90L, 0x563C5F93L,
            0x082F63B7L, 0xFA44E0B4L, 0xE9141340L, 0x1B7F9043L,
            0xCFB5F4A8L, 0x3DDE77ABL, 0x2E8E845FL, 0xDCE5075CL,
            0x92A8FC17L, 0x60C37F14L, 0x73938CE0L, 0x81F80FE3L,
            0x55326B08L, 0xA759E80BL, 0xB4091BFFL, 0x466298FCL,
            0x1871A4D8L, 0xEA1A27DBL, 0xF94AD42FL, 0x0B21572CL,
            0xDFEB33C7L, 0x2D80B0C4L, 0x3ED04330L, 0xCCBBC033L,
            0xA24BB5A6L, 0x502036A5L, 0x4370C551L, 0xB11B4652L,
            0x65D122B9L, 0x97BAA1BAL, 0x84EA524EL, 0x7681D14DL,
            0x2892ED69L, 0xDAF96E6AL, 0xC9A99D9EL, 0x3BC21E9DL,
            0xEF087A76L, 0x1D63F975L, 0x0E330A81L, 0xFC588982L,
            0xB21572C9L, 0x407EF1CAL, 0x532E023EL, 0xA145813DL,
            0x758FE5D6L, 0x87E466D5L, 0x94B49521L, 0x66DF1622L,
            0x38CC2A06L, 0xCAA7A905L, 0xD9F75AF1L, 0x2B9CD9F2L,
            0xFF56BD19L, 0x0D3D3E1AL, 0x1E6DCDEEL, 0xEC064EEDL,
            0xC38D26C4L, 0x31E6A5C7L, 0x22B65633L, 0xD0DDD530L,
            0x0417B1DBL, 0xF67C32D8L, 0xE52CC12CL, 0x1747422FL,
            0x49547E0BL, 0xBB3FFD08L, 0xA86F0EFCL, 0x5A048DFFL,
            0x8ECEE914L, 0x7CA56A17L, 0x6FF599E3L, 0x9D9E1AE0L,
            0xD3D3E1ABL, 0x21B862A8L, 0x32E8915CL, 0xC083125FL,
            0x144976B4L, 0xE622F5B7L, 0xF5720643L, 0x07198540L,
            0x590AB964L, 0xAB613A67L, 0xB831C993L, 0x4A5A4A90L,
            0x9E902E7BL, 0x6CFBAD78L, 0x7FAB5E8CL, 0x8DC0DD8FL,
            0xE330A81AL, 0x115B2B19L, 0x020BD8EDL, 0xF0605BEEL,
            0x24AA3F05L, 0xD6C1BC06L, 0xC5914FF2L, 0x37FACCF1L,
            0x69E9F0D5L, 0x9B8273D6L, 0x88D28022L, 0x7AB90321L,
            0xAE7367CAL, 0x5C18E4C9L, 0x4F48173DL, 0xBD23943EL,
            0xF36E6F75L, 0x0105EC76L, 0x12551F82L, 0xE03E9C81L,
            0x34F4F86AL, 0xC69F7B69L, 0xD5CF889DL, 0x27A40B9EL,
            0x79B737BAL, 0x8BDCB4B9L, 0x988C474DL, 0x6AE7C44EL,
            0xBE2DA0A5L, 0x4C4623A6L, 0x5F16D052L, 0xAD7D5351L,
        };

        int i;
        unsigned long crc32 = 0xffffffffL;
        unsigned long result;
        unsigned char byte0, byte1, byte2, byte3;

        for (i = 0; i < len; i++) {
            crc32 = (crc32 >> 8) ^ crc_c[(crc32 ^ (buf[i])) & 0xFF];
        }

        result = ~crc32;

        /*  result now holds the negated polynomial remainder;
        *  since the table and algorithm is "reflected" [williams95].
        *  That is, result has the same value as if we mapped the message
        *  to a polynomial, computed the host-bit-order polynomial
        *  remainder, performed final negation, then did an end-for-end
        *  bit-reversal.
        *  Note that a 32-bit bit-reversal is identical to four inplace
        *  8-bit reversals followed by an end-for-end byteswap.
        *  In other words, the bytes of each bit are in the right order,
        *  but the bytes have been byteswapped.  So we now do an explicit
        *  byteswap.  On a little-endian machine, this byteswap and
        *  the final ntohl cancel out and could be elided.
        */

        byte0 = result & 0xff;
        byte1 = (result >> 8) & 0xff;
        byte2 = (result >> 16) & 0xff;
        byte3 = (result >> 24) & 0xff;
        crc32 = ((byte0 << 24) | (byte1 << 16) | (byte2 << 8) | byte3);
        return crc32;
    }

private:
    static void NrandAddRandom(NrandHandle_t *rand, unsigned char *buf, int len) 
    {
        int i;
        unsigned char si;

        /* Mix entropy in buf with s[]...
        *
        * This is the ARC4 key-schedule.  It is rather poor and doesn't mix
        * the key in very well.  This causes a bias at the start of the stream.
        * To eliminate most of this bias, the first N bytes of the stream should
        * be dropped.
        */
        rand->i--;
        for (i = 0; i < 256; i++) {
            rand->i = (rand->i + 1);
            si = rand->s[rand->i];
            rand->j = (rand->j + si + buf[i % len]);
            rand->s[rand->i] = rand->s[rand->j];
            rand->s[rand->j] = si;
        }
        rand->j = rand->i;
    }

    static unsigned char NrandGetByte(NrandHandle_t *r) 
    {
        unsigned char si, sj;

        /* This is the core of ARC4 and provides the pseudo-randomness */
        r->i = (r->i + 1);
        si = r->s[r->i];
        r->j = (r->j + si);
        sj = r->s[r->j];
        r->s[r->i] = sj; /* The start of the the swap */
        r->s[r->j] = si; /* The other half of the swap */
        return (r->s[(si + sj) & 0xff]);
    }

    static int NrandGet(NrandHandle_t *r, void *buf, size_t len)
    {
        unsigned char *p;
        size_t i;

        /* Hand out however many bytes were asked for */
        for (p = (unsigned char*)buf, i = 0; i < len; i++) {
            p[i] = NrandGetByte(r);
        }
        return (0);
    }

    static void NrandInit(NrandHandle_t *r) 
    {
        unsigned char seed[256]; /* Starts out with "random" stack data */
        int i;

        /* Gather seed entropy with best the OS has to offer */
#if defined(_MSC_VER)
        HCRYPTPROV hcrypt = 0;

        CryptAcquireContext(&hcrypt, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
        CryptGenRandom(hcrypt, sizeof(seed), seed);
        CryptReleaseContext(hcrypt, 0);
#elif defined(__GNUC__)
        struct timeval *tv = (struct timeval *)seed;
        int *pid = (int *)(seed + sizeof(*tv));
        int fd;

        gettimeofday(tv, NULL); /* fill lowest seed[] with time */
        *pid = getpid();        /* fill next lowest seed[] with pid */

                                /* Try to fill the rest of the state with OS provided entropy */
        if ((fd = open("/dev/urandom", O_RDONLY)) != -1 ||
            (fd = open("/dev/arandom", O_RDONLY)) != -1) {
            ssize_t n;
            do {
                errno = 0;
                n = read(fd, seed + sizeof(*tv) + sizeof(*pid), sizeof(seed) - sizeof(*tv) - sizeof(*pid));
            } while (n < 0 && errno == EINTR);
            close(fd);
        }
#else
#error unsupported compiler
#endif

        /* Fill up our handle with starter values */
        for (i = 0; i < 256; i++) { 
            r->s[i] = i; 
        }
        r->i = r->j = 0;

        NrandAddRandom(r, seed, 128); /* lower half of seed data for entropy */
        NrandAddRandom(r, seed + 128, 128); /* Now use upper half */
        r->tmp = NULL;
        r->tmplen = 0;

        /* This stream will start biased.  Get rid of 1K of the stream */
        NrandGet(r, seed, 256); 
        NrandGet(r, seed, 256);
        NrandGet(r, seed, 256); 
        NrandGet(r, seed, 256);
    }

    static unsigned long UpdateCRC(unsigned long crc, const unsigned char *buf, int len)
    {
        /* Table of CRCs of all 8-bit messages. */
        static unsigned long crc_table[256];
        /* Flag: has the table been computed? Initially false. */
        static bool crc_table_computed = false;
        static std::mutex crc_table_init_lock;

        unsigned long c = crc ^ 0xffffffffL;
        int n;

        {
            std::unique_lock<std::mutex> lock(crc_table_init_lock);
            if (!crc_table_computed) {
                MakeCRCTable(crc_table);
                crc_table_computed = true;
            }
        }

        for (n = 0; n < len; n++) {
            c = crc_table[(c ^ buf[n]) & 0xff] ^ (c >> 8);
        }
        return c ^ 0xffffffffL;
    }

    /* Make the table for a fast CRC. */
    static void MakeCRCTable(unsigned long *crc_table)
    {
        unsigned long c;
        int n, k;

        for (n = 0; n < 256; n++) {
            c = (unsigned long)n;
            for (k = 0; k < 8; k++) {
                if (c & 1) {
                    c = 0xedb88320L ^ (c >> 1);
                }
                else {
                    c = c >> 1;
                }
            }
            crc_table[n] = c;
        }
    }
};

#endif