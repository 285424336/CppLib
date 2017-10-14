#ifndef BASE64_H_INCLUDED
#define BASE64_H_INCLUDED

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <fstream>

class Base64Encoder
{
public:
    /**
    *get the minimum buf size need to encrypt the input size
    *in(in): the input size 
    *return the minimum outbuf size
    */
    static size_t CalOutBufNeedSize(size_t in)
    {
        return in / 3 * 4 + (in % 3 ? 4 : 0);
    }

    /**
    *use base64 to encrypt the bytes
    *input(in): the bytes need to encrypt
    *input_size(in): size of input
    *output(out): point to the output buf
    *output_size(in/out): input the output buf len, output the remain unused buf len
    *if success return true, else return false
    */
    static bool Encrypt(const uint8_t *input, size_t input_size, uint8_t* output, size_t *output_size)
    {
        std::string r;
        if (input == NULL || input_size == 0 || output == NULL) {
            return false;
        }
        size_t tmp_len = *output_size;
        Base64Encoder en;
        if (!en.ProcessBytes(input, input_size, output, output_size)) {
            return false;
        }
        if (!en.ProcessEnd(output + tmp_len - *output_size, output_size)) {
            return false;
        }
        return true;
    }

    /**
    *use base64 to encrypt the bytes
    *input(in): the bytes need to encrypt
    *input_size(in): size of input
    *return the string after encrypt
    */
    static std::string Encrypt(const uint8_t *input, size_t input_size)
    {
        std::string r;
        if (input == NULL || input_size == 0) {
            return "";
        }
        size_t out_len = CalOutBufNeedSize(input_size);
        unsigned char *buf = new (std::nothrow) unsigned char[out_len];
        if (buf == NULL) {
            return "";
        }
        size_t remain_len = out_len;
        if (Encrypt(input, input_size, buf, &remain_len)) {
            r = std::string((char *)buf, out_len - remain_len);
        }
        if (buf) {
            delete[]buf;
            buf = NULL;
        }
        return r;
    }

    /**
    *use base64 to encrypt the bytes
    *input(in): the string bytes need to encrypt
    *return the string after encrypt
    */
    static std::string Encrypt(const std::string &input)
    {
        return Encrypt((const unsigned char *)input.c_str(), input.size());
    }

    /**
    *use base64 to encrypt the file
    *in_file_path(in): the file need to encrypt
    *out_file_path(in): the file need to save the encrypt result
    *return the string after encrypt
    *note in_file_path can not be the same
    */
    static bool Encrypt(const std::string &in_file_path, const std::string &out_file_path)
    {
        uint8_t chunk_in[768];
        uint8_t chunk_out[1024];

        std::ifstream in(in_file_path, std::ios::binary);
        if (!in.good()) return false;
        std::ofstream out(out_file_path, std::ios::binary);
        if (!out.good()) return false;

        in.seekg(0, std::ios_base::end);
        auto file_size = in.tellg();
        in.seekg(0, std::ios_base::beg);

        Base64Encoder en;
        size_t remains = (size_t)file_size;
        for (;remains;) {
            size_t read_len = remains > sizeof(chunk_in) ? sizeof(chunk_in) : remains;
            in.read(reinterpret_cast<char*>(chunk_in), read_len);
            remains -= read_len;
            if (in.fail()) {
                return false;
            }
            size_t out_len = sizeof(chunk_out);
            if (!en.ProcessBytes(chunk_in, read_len, chunk_out, &out_len)) {
                return false;
            }
            out.write(reinterpret_cast<const char*>(chunk_out), sizeof(chunk_out) - out_len);
            if (out.fail()) {
                return false;
            }
            if (!remains) {
                out_len = sizeof(chunk_out);
                if (!en.ProcessEnd(chunk_out, &out_len)) {
                    return false;
                }
                out.write(reinterpret_cast<const char*>(chunk_out), sizeof(chunk_out) - out_len);
                if (out.fail()) {
                    return false;
                }
            }
        }
        return true;
    }

public:
    Base64Encoder()
    {
        memset(m_buf, 0, sizeof(m_buf));
        m_buf_size = 0;
    }
    Base64Encoder(const Base64Encoder&) = delete;
    Base64Encoder &operator=(const Base64Encoder&) = delete;

    /**
    *use base64 to encrypt the bytes
    *input(in): one byte need to be encrypt
    *output(out): point to the output buf
    *output_size(in/out): input the output buf len, output the remain unused buf len
    *if success return true, else return false
    */
    inline bool ProcessByte(const uint8_t input, uint8_t* output, size_t *output_size)
    {
        m_buf[m_buf_size++] = input;
        if (m_buf_size == 3) {
            return EncodeQuantum(output, output_size);
        }
        return true;
    }

    /**
    *use base64 to encrypt the bytes
    *input(in): the bytes need to encrypt
    *input_size(in): size of input
    *output(out): point to the output buf
    *output_size(in/out): input the output buf len, output the remain unused buf len
    *if success return true, else return false
    */
    inline bool ProcessBytes(const uint8_t *input, size_t input_size, uint8_t* output, size_t *output_size)
    {
        if (input == NULL) {
            return false;
        }
        while (input_size--) {
            size_t tmp = *output_size;
            if (!ProcessByte(*input++, output, output_size)) {
                return false;
            }
            output += tmp - *output_size;
        }
        return true;
    }

    /**
    *use base64 to encrypt the bytes, when you after input the last byte, you should call this
    *output(out): point to the output buf
    *output_size(in/out): input the output buf len, output the remain unused buf len
    *if success return true, else return false
    */
    inline bool ProcessEnd(uint8_t* output, size_t *output_size)
    {
        if (m_buf_size) {
            for (int i = m_buf_size; i < 3; i++)  {
                m_buf[i] = 0;
            }
            return EncodeQuantum(output, output_size);
        }
        return true;
    }

private:
    inline bool EncodeQuantum(uint8_t* output, size_t *output_size)
    {
        static const unsigned char map[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        static const unsigned char padding = '=';

        if (output == NULL || output_size == NULL || *output_size < 4) {
            m_buf_size = 0;
            return false;
        }
        uint8_t out;
        out = (m_buf[0] & 0xFC) >> 2;
        output[0] = map[out];
        out = ((m_buf[0] & 0x03) << 4) | (m_buf[1] >> 4);
        output[1] = map[out];
        out = ((m_buf[1] & 0x0F) << 2) | (m_buf[2] >> 6);
        output[2] = m_buf_size > 1 ? map[out] : padding;
        out = m_buf[2] & 0x3F;
        output[3] = m_buf_size > 2 ? map[out] : padding;
        m_buf_size = 0;
        *output_size -= 4;
        return true;
    }

private:
    // Data members
    unsigned char m_buf[3];
    unsigned int  m_buf_size;
};

class Base64Decoder
{
public:
    /**
    *get the minimum buf size need to decrypt the input size
    *in(in): the input size
    *return the minimum outbuf size
    */
    static size_t CalOutBufNeedSize(size_t in)
    {
        return in / 4 * 3 + (in % 4 ? 3 : 0);
    }

    /**
    *use base64 to decrypt the bytes
    *input(in): the bytes need to decrypt
    *input_size(in): size of input
    *output(out): point to the output buf
    *output_size(in/out): input the output buf len, output the remain unused buf len
    *if success return true, else return false
    */
    static bool Decrypt(const uint8_t *input, size_t input_size, uint8_t* output, size_t *output_size)
    {
        std::string r;
        if (input == NULL || input_size == 0 || output == NULL || output_size == NULL) {
            return false;
        }
        size_t tmp_len = *output_size;
        Base64Decoder de;
        if (!de.ProcessBytes(input, input_size, output, output_size)) {
            return false;
        }
        if (!de.ProcessEnd(output + tmp_len - *output_size, output_size)) {
            return false;
        }
        return true;
    }

    /**
    *use base64 to decrypt the bytes
    *input(in): the bytes need to decrypt
    *input_size(in): size of input
    *return the string after decrypt
    */
    static std::string Decrypt(const uint8_t *input, size_t input_size)
    {
        std::string r;
        if (input == NULL || input_size == 0) {
            return "";
        }
        size_t out_len = CalOutBufNeedSize(input_size);
        unsigned char *buf = new (std::nothrow) unsigned char[out_len];
        if (buf == NULL) {
            return "";
        }
        size_t remain_len = out_len;
        if (Decrypt(input, input_size, buf, &remain_len)) {
            r = std::string((char *)buf, out_len - remain_len);
        }
        if (buf) {
            delete[]buf;
            buf = NULL;
        }
        return r;
    }

    /**
    *use base64 to decrypt the bytes
    *input(in): the string bytes need to decrypt
    *return the string after decrypt
    */
    static std::string Decrypt(const std::string &input)
    {
        return Decrypt((const unsigned char *)input.c_str(), input.size());
    }

    /**
    *use base64 to decrypt the file
    *in_file_path(in): the file need to decrypt
    *out_file_path(in): the file need to save the decrypt result
    *return the string after decrypt
    *note in_file_path can not be the same
    */
    static bool Decrypt(const std::string &in_file_path, const std::string &out_file_path)
    {
        uint8_t chunk_in[768];
        uint8_t chunk_out[1024];

        std::ifstream in(in_file_path, std::ios::binary);
        if (!in.good()) return false;
        std::ofstream out(out_file_path, std::ios::binary);
        if (!out.good()) return false;

        in.seekg(0, std::ios_base::end);
        auto file_size = in.tellg();
        in.seekg(0, std::ios_base::beg);

        Base64Decoder de;
        size_t remains = (size_t)file_size;
        for (; remains;) {
            size_t read_len = remains > sizeof(chunk_in) ? sizeof(chunk_in) : remains;
            in.read(reinterpret_cast<char*>(chunk_in), read_len);
            remains -= read_len;
            if (in.fail()) {
                return false;
            }
            size_t out_len = sizeof(chunk_out);
            if (!de.ProcessBytes(chunk_in, read_len, chunk_out, &out_len)) {
                return false;
            }
            out.write(reinterpret_cast<const char*>(chunk_out), sizeof(chunk_out) - out_len);
            if (out.fail()) {
                return false;
            }
            if (!remains) {
                out_len = sizeof(chunk_out);
                if (!de.ProcessEnd(chunk_out, &out_len)) {
                    return false;
                }
                out.write(reinterpret_cast<const char*>(chunk_out), sizeof(chunk_out) - out_len);
                if (out.fail()) {
                    return false;
                }
            }
        }
        return true;
    }

public:
    Base64Decoder()
    {
        memset(m_buf, 0, sizeof(m_buf));
        m_buf_size = 0;
    }
    Base64Decoder(const Base64Decoder&) = delete;
    Base64Decoder &operator=(const Base64Decoder&) = delete;

    /**
    *use base64 to decrypt the bytes
    *input(in): one byte need to be decrypt
    *output(out): point to the output buf
    *output_size(in/out): input the output buf len, output the remain unused buf len
    *if success return true, else return false
    */
    inline bool ProcessByte(const uint8_t input, uint8_t* output, size_t *output_size)
    {
        char i = ConvToNumber(input);
        if (i >= 0) {
            m_buf[m_buf_size++] = (unsigned char)i;
        }
        if (m_buf_size == 4) {
            return DecodeQuantum(output, output_size);
        }
        return true;
    }

    /**
    *use base64 to decrypt the bytes
    *input(in): the bytes need to decrypt
    *input_size(in): size of input
    *output(out): point to the output buf
    *output_size(in/out): input the output buf len, output the remain unused buf len
    *if success return true, else return false
    */
    inline bool ProcessBytes(const uint8_t *input, size_t input_size, uint8_t* output, size_t *output_size)
    {
        if (input == NULL) {
            return false;
        }
        while (input_size--) {
            size_t tmp = *output_size;
            if (!ProcessByte(*input++, output, output_size)) {
                return false;
            }
            output += tmp - *output_size;
        }
        return true;
    }

    /**
    *use base64 to decrypt the bytes, when you after input the last byte, you should call this
    *output(out): point to the output buf
    *output_size(in/out): input the output buf len, output the remain unused buf len
    *if success return true, else return false
    */
    inline bool ProcessEnd(uint8_t* output, size_t *output_size)
    {
        if (m_buf_size) {
            for (int i = m_buf_size; i < 4; i++) {
                m_buf[i] = 0;
            }
            return DecodeQuantum(output, output_size);
        }
        return true;
    }

private:
    inline char ConvToNumber(char inByte)
    {
        if (inByte >= 'A' && inByte <= 'Z')
            return (inByte - 'A');

        if (inByte >= 'a' && inByte <= 'z')
            return (inByte - 'a' + 26);

        if (inByte >= '0' && inByte <= '9')
            return (inByte - '0' + 52);

        if (inByte == '+')
            return (62);

        if (inByte == '/')
            return (63);

        return (-1);
    }

    inline bool DecodeQuantum(uint8_t* output, size_t *output_size)
    {
        if (output == NULL || output_size == NULL) {
            m_buf_size = 0;
            return false;
        }
        if (!*output_size) {
            return false;
        }
        --*output_size;
        uint8_t out;
        out = (m_buf[0] << 2) | (m_buf[1] >> 4);
        output[0] = out;
        out = (m_buf[1] << 4) | (m_buf[2] >> 2);
        if (m_buf_size > 2) {
            if (!*output_size) {
                return false;
            }
            --*output_size;
            output[1] = out;
        }
        out = (m_buf[2] << 6) | m_buf[3];
        if (m_buf_size > 3) {
            if (!*output_size) {
                return false;
            }
            --*output_size;
            output[2] = out;
        }
        m_buf_size = 0;
        return true;
    }

private:
    // Data members
    unsigned char m_buf[4];
    unsigned int  m_buf_size;
};

#endif