#ifndef _SALSA20HELPER_H_
#define _SALSA20HELPER_H_

#include "Salsa20.h"
#include <fstream>
#include <string>

class Salsa20Helper
    : public Salsa20
{
public:
    enum
    {
        NUM_OF_BLOCKS_PER_CHUNK = 16,
    };

    /**
    * \key[in] the key should be 32 bytes
    * \iv[in] the iv should be 8 bytes
    */
    Salsa20Helper(uint8_t *key = NULL, uint8_t *iv = NULL) : Salsa20(key)
    {
        if (iv != NULL) this->setIv(iv);
    }

    /**
    * \in[in] the stream want to transfer
    * \out[in_out] the stream that has transfered
    * \size[in] the stream size of in and out
    * \return true | false
    */
    bool Transfer(const uint8_t *in, uint8_t *out, size_t size)
    {
        if (!in || !out) return false;

        auto blocks = size / Salsa20::BLOCK_SIZE;
        auto remains = size % Salsa20::BLOCK_SIZE;

        if (blocks > 0) this->processBlocks(in, out, blocks);
        if (remains > 0) this->processBytes(&in[size - remains], &out[size - remains], remains);

        return true;
    }

    /**
    * \in[in] the stream want to transfer
    * \return the transfered stream
    */
    std::string Transfer(const std::string &in)
    {
        if (in.empty())
        {
            return "";
        }

        uint8_t *out = new (std::nothrow) uint8_t[in.size()];
        if (out == NULL)
        {
            return "";
        }

        auto ret = Transfer((const uint8_t *)in.c_str(), out, in.size());
        if (!ret)
        {
            delete[]out;
            return "";
        }
        std::string result((char *)out, in.size());
        delete[]out;
        return result;
    }

    /**
    * \in_file_path[in] the file want to transfer
    * \out_file_path[in] the file that has transfered
    * \return true | false
    */
    bool Transfer(const std::string &in_file_path, const std::string &out_file_path)
    {
        uint8_t chunk[NUM_OF_BLOCKS_PER_CHUNK * Salsa20::BLOCK_SIZE] = { 0 };

        std::ifstream in(in_file_path, std::ios::binary);
        if (!in.good()) return false;
        std::ofstream out(out_file_path, std::ios::binary);
        if (!out.good()) return false;

        in.seekg(0, std::ios_base::end);
        auto file_size = in.tellg();
        in.seekg(0, std::ios_base::beg);

        auto nums = file_size / sizeof(chunk);
        auto remains = file_size % sizeof(chunk);

        for (decltype(nums) i = 0; i < nums; ++i)
        {
            in.read(reinterpret_cast<char*>(chunk), sizeof(chunk));
            if (in.fail()) return false;
            this->processBlocks(chunk, chunk, NUM_OF_BLOCKS_PER_CHUNK);
            out.write(reinterpret_cast<const char*>(chunk), sizeof(chunk));
            if (out.fail()) return false;
        }

        if (remains > 0)
        {
            in.read(reinterpret_cast<char*>(chunk), remains);
            if (in.fail()) return false;
            this->processBytes(chunk, chunk, (size_t)remains);
            out.write(reinterpret_cast<const char*>(chunk), remains);
            if (out.fail()) return false;
        }

        return true;
    }
};

#endif