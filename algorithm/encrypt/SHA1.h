#ifndef SHA1_H_INCLUDED
#define SHA1_H_INCLUDED

#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <fstream>

class SHA1
{
private:
    static const size_t BLOCK_INTS = 16;  /* number of 32bit integers per SHA1 block */
    static const size_t BLOCK_BYTES = BLOCK_INTS * 4;

private:
    static void Reset(uint32_t digest[], std::string &buffer, uint64_t &transforms)
    {
        /* SHA1 initialization constants */
        digest[0] = 0x67452301;
        digest[1] = 0xefcdab89;
        digest[2] = 0x98badcfe;
        digest[3] = 0x10325476;
        digest[4] = 0xc3d2e1f0;

        /* Reset counters */
        buffer.clear();
        transforms = 0;
    }

    static uint32_t rol(const uint32_t value, const size_t bits)
    {
        return (value << bits) | (value >> (32 - bits));
    }

    static uint32_t blk(const uint32_t block[BLOCK_INTS], const size_t i)
    {
        return rol(block[(i + 13) & 15] ^ block[(i + 8) & 15] ^ block[(i + 2) & 15] ^ block[i], 1);
    }

    /*
    * (R0+R1), R2, R3, R4 are the different operations used in SHA1
    */
    static void R0(const uint32_t block[BLOCK_INTS], const uint32_t v, uint32_t &w, const uint32_t x, const uint32_t y, uint32_t &z, const size_t i)
    {
        z += ((w&(x^y)) ^ y) + block[i] + 0x5a827999 + rol(v, 5);
        w = rol(w, 30);
    }

    static void R1(uint32_t block[BLOCK_INTS], const uint32_t v, uint32_t &w, const uint32_t x, const uint32_t y, uint32_t &z, const size_t i)
    {
        block[i] = blk(block, i);
        z += ((w&(x^y)) ^ y) + block[i] + 0x5a827999 + rol(v, 5);
        w = rol(w, 30);
    }

    static void R2(uint32_t block[BLOCK_INTS], const uint32_t v, uint32_t &w, const uint32_t x, const uint32_t y, uint32_t &z, const size_t i)
    {
        block[i] = blk(block, i);
        z += (w^x^y) + block[i] + 0x6ed9eba1 + rol(v, 5);
        w = rol(w, 30);
    }

    static void R3(uint32_t block[BLOCK_INTS], const uint32_t v, uint32_t &w, const uint32_t x, const uint32_t y, uint32_t &z, const size_t i)
    {
        block[i] = blk(block, i);
        z += (((w | x)&y) | (w&x)) + block[i] + 0x8f1bbcdc + rol(v, 5);
        w = rol(w, 30);
    }

    static void R4(uint32_t block[BLOCK_INTS], const uint32_t v, uint32_t &w, const uint32_t x, const uint32_t y, uint32_t &z, const size_t i)
    {
        block[i] = blk(block, i);
        z += (w^x^y) + block[i] + 0xca62c1d6 + rol(v, 5);
        w = rol(w, 30);
    }

    /*
    * Hash a single 512-bit block. This is the core of the algorithm.
    */
    static void transform(uint32_t digest[], uint32_t block[BLOCK_INTS], uint64_t &transforms)
    {
        /* Copy digest[] to working vars */
        uint32_t a = digest[0];
        uint32_t b = digest[1];
        uint32_t c = digest[2];
        uint32_t d = digest[3];
        uint32_t e = digest[4];

        /* 4 rounds of 20 operations each. Loop unrolled. */
        R0(block, a, b, c, d, e, 0);
        R0(block, e, a, b, c, d, 1);
        R0(block, d, e, a, b, c, 2);
        R0(block, c, d, e, a, b, 3);
        R0(block, b, c, d, e, a, 4);
        R0(block, a, b, c, d, e, 5);
        R0(block, e, a, b, c, d, 6);
        R0(block, d, e, a, b, c, 7);
        R0(block, c, d, e, a, b, 8);
        R0(block, b, c, d, e, a, 9);
        R0(block, a, b, c, d, e, 10);
        R0(block, e, a, b, c, d, 11);
        R0(block, d, e, a, b, c, 12);
        R0(block, c, d, e, a, b, 13);
        R0(block, b, c, d, e, a, 14);
        R0(block, a, b, c, d, e, 15);
        R1(block, e, a, b, c, d, 0);
        R1(block, d, e, a, b, c, 1);
        R1(block, c, d, e, a, b, 2);
        R1(block, b, c, d, e, a, 3);
        R2(block, a, b, c, d, e, 4);
        R2(block, e, a, b, c, d, 5);
        R2(block, d, e, a, b, c, 6);
        R2(block, c, d, e, a, b, 7);
        R2(block, b, c, d, e, a, 8);
        R2(block, a, b, c, d, e, 9);
        R2(block, e, a, b, c, d, 10);
        R2(block, d, e, a, b, c, 11);
        R2(block, c, d, e, a, b, 12);
        R2(block, b, c, d, e, a, 13);
        R2(block, a, b, c, d, e, 14);
        R2(block, e, a, b, c, d, 15);
        R2(block, d, e, a, b, c, 0);
        R2(block, c, d, e, a, b, 1);
        R2(block, b, c, d, e, a, 2);
        R2(block, a, b, c, d, e, 3);
        R2(block, e, a, b, c, d, 4);
        R2(block, d, e, a, b, c, 5);
        R2(block, c, d, e, a, b, 6);
        R2(block, b, c, d, e, a, 7);
        R3(block, a, b, c, d, e, 8);
        R3(block, e, a, b, c, d, 9);
        R3(block, d, e, a, b, c, 10);
        R3(block, c, d, e, a, b, 11);
        R3(block, b, c, d, e, a, 12);
        R3(block, a, b, c, d, e, 13);
        R3(block, e, a, b, c, d, 14);
        R3(block, d, e, a, b, c, 15);
        R3(block, c, d, e, a, b, 0);
        R3(block, b, c, d, e, a, 1);
        R3(block, a, b, c, d, e, 2);
        R3(block, e, a, b, c, d, 3);
        R3(block, d, e, a, b, c, 4);
        R3(block, c, d, e, a, b, 5);
        R3(block, b, c, d, e, a, 6);
        R3(block, a, b, c, d, e, 7);
        R3(block, e, a, b, c, d, 8);
        R3(block, d, e, a, b, c, 9);
        R3(block, c, d, e, a, b, 10);
        R3(block, b, c, d, e, a, 11);
        R4(block, a, b, c, d, e, 12);
        R4(block, e, a, b, c, d, 13);
        R4(block, d, e, a, b, c, 14);
        R4(block, c, d, e, a, b, 15);
        R4(block, b, c, d, e, a, 0);
        R4(block, a, b, c, d, e, 1);
        R4(block, e, a, b, c, d, 2);
        R4(block, d, e, a, b, c, 3);
        R4(block, c, d, e, a, b, 4);
        R4(block, b, c, d, e, a, 5);
        R4(block, a, b, c, d, e, 6);
        R4(block, e, a, b, c, d, 7);
        R4(block, d, e, a, b, c, 8);
        R4(block, c, d, e, a, b, 9);
        R4(block, b, c, d, e, a, 10);
        R4(block, a, b, c, d, e, 11);
        R4(block, e, a, b, c, d, 12);
        R4(block, d, e, a, b, c, 13);
        R4(block, c, d, e, a, b, 14);
        R4(block, b, c, d, e, a, 15);

        /* Add the working vars back into digest[] */
        digest[0] += a;
        digest[1] += b;
        digest[2] += c;
        digest[3] += d;
        digest[4] += e;

        /* Count the number of transformations */
        transforms++;
    }

    /* 
    *Convert the std::string (byte buffer) to a uint32_t array (MSB) 
    */
    static void buffer_to_block(const std::string &buffer, uint32_t block[BLOCK_INTS])
    {
        for (size_t i = 0; i < BLOCK_INTS; i++)
        {
            block[i] = (buffer[4 * i + 3] & 0xff)
                | (buffer[4 * i + 2] & 0xff) << 8
                | (buffer[4 * i + 1] & 0xff) << 16
                | (buffer[4 * i + 0] & 0xff) << 24;
        }
    }

public:
    SHA1()
    {
        in_buf.reserve(BLOCK_BYTES);
        Reset(digest, in_buf, transform_count);
    }
    SHA1(const SHA1&) = delete;
    SHA1 &operator=(const SHA1&) = delete;

    /**
    *get the sha1 from the input byte
    *byte(in): the byte need to cal sha1
    *byte_size(in): byte size
    *return sha1 string, failed return empty
    */
    std::string sha1(const unsigned char *byte, size_t byte_size)
    {
        if (byte == NULL || byte_size == 0)
        {
            return "";
        }
        Update(byte, byte_size);
        return Final();
    }

    /**
    *get the sha1 from the file
    *f(in): file path
    *return sha1 string, failed return empty
    */
    std::string sha1(const std::string &f)
    {
        std::ifstream stream(f.c_str(), std::ios::binary);
        if (!stream.good())
        {
            return "";
        }
        Update(stream);
        return Final();
    }

    /**
    *get the sha1 from the input stream
    *istream(in): input stream
    *return sha1 string, failed return empty
    */
    std::string sha1(std::istream &istream)
    {
        if (istream.good())
        {
            return "";
        }
        Update(istream);
        return Final();
    }

    /**
    *update the sha1 from the input byte
    *byte(in): the byte need to cal sha1
    *byte_size(in): byte size
    */
    void Update(const unsigned char *byte, size_t byte_size)
    {
        if (byte == NULL || byte_size == 0)
        {
            return;
        }

        while (true)
        {
            size_t deal_size = byte_size > (BLOCK_BYTES - in_buf.size()) ? (BLOCK_BYTES - in_buf.size()) : byte_size;
            in_buf.append((char *)byte, deal_size);
            byte += deal_size;
            byte_size -= deal_size;
            if (in_buf.size() != BLOCK_BYTES)
            {
                return;
            }
            uint32_t block[BLOCK_INTS];
            buffer_to_block(in_buf, block);
            transform(digest, block, transform_count);
            in_buf.clear();
        }
    }

    /**
    *update the sha1 from the input string
    *s(in): input string
    */
    void Update(const std::string &s)
    {
        Update((unsigned char *)s.c_str(), s.size());
    }

    /**
    *update the sha1 from the input stream
    *is(in): input stream
    */
    void Update(std::istream &is)
    {
        while (true)
        {
            char sbuf[BLOCK_BYTES];
            is.read(sbuf, BLOCK_BYTES - in_buf.size());
            in_buf.append(sbuf, (size_t)is.gcount());
            if (in_buf.size() != BLOCK_BYTES)
            {
                return;
            }
            uint32_t block[BLOCK_INTS];
            buffer_to_block(in_buf, block);
            transform(digest, block, transform_count);
            in_buf.clear();
        }
    }

    /**
    *update and get the sha1 hex string
    */
    std::string Final()
    {
        /* Total number of hashed bits */
        uint64_t total_bits = (transform_count*BLOCK_BYTES + in_buf.size()) * 8;

        /* Padding */
        in_buf += (char)0x80;
        size_t orig_size = in_buf.size();
        while (in_buf.size() < BLOCK_BYTES)
        {
            in_buf += (char)0x00;
        }

        uint32_t block[BLOCK_INTS];
        buffer_to_block(in_buf, block);
        if (orig_size > BLOCK_BYTES - 8)
        {
            transform(digest, block, transform_count);
            for (size_t i = 0; i < BLOCK_INTS - 2; i++)
            {
                block[i] = 0;
            }
        }

        /* Append total_bits, split this uint64_t into two uint32_t */
        block[BLOCK_INTS - 1] = (uint32_t)total_bits;
        block[BLOCK_INTS - 2] = (total_bits >> 32);
        transform(digest, block, transform_count);

        /* Hex std::string */
        std::ostringstream result;
        for (size_t i = 0; i < sizeof(digest) / sizeof(digest[0]); i++)
        {
            result << std::hex << std::setfill('0') << std::setw(8);
            result << digest[i];
        }

        /* Reset for next run */
        Reset(digest, in_buf, transform_count);
        return result.str();
    }

private:
    uint32_t digest[5];
    std::string in_buf;
    uint64_t transform_count;
};

#endif