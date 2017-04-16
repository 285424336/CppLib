#ifndef ALGORITHM_HELPER_H_INCLUDED
#define ALGORITHM_HELPER_H_INCLUDED

class AlgorithmHelper
{
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

};

#endif