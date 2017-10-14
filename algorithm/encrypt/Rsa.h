#ifndef RSA_H_INCLUDED
#define RSA_H_INCLUDED

#include "BigInt.h"
#include <sstream>

class RSA
{
public:
    /**
    *public_key: need to be a prime number
    *private_key: need to be a prime number, empty for init
    *pp_info: need to be a prime number, empty for init
    */
    RSA(const std::string &public_key, const std::string &private_key, const std::string &pp_info) :_e(public_key), _d(private_key), _N(pp_info)
    {
    }

    /**
    *public_key: need to be a prime number
    *private_key: need to be a prime number, empty for init
    *pp_info: need to be a prime number, empty for init
    */
    RSA(const BigInt &public_key = BigInt(65537), const BigInt &private_key = BigInt(), const BigInt &pp_info = BigInt()) :_e(public_key), _d(private_key), _N(pp_info)
    {
    }

    ~RSA()
    {
    }

    /**
    *reinit the encrypt key and info key N
    *n(in): the bit num of N
    */
    void ReInitKeys(unsigned int n)
    {
        //init the seed of rand
        srand(time(NULL));
        //set the max big int bit num
        BigInt::SetMaxBigIntBitNum(n);
        //get a prime big int number, check 10 count
        BigInt p = CreatePrime(n, 10);
        BigInt q = CreatePrime(n, 10);
        BigInt ol = (p - 1)*(q - 1);
        //make the private key
        MakePrivateKey(ol);
        //get the public info
        _N = p*q;
    }

    /**
    *encrypt the number
    *m(in): number need to encrypt
    *return encrypted number
    */
    BigInt EncryptByPu(const BigInt& m)
    {
        return m.Moden(_e, _N);
    }

    /**
    *decrypt the number
    *c(in): number need to decrypt
    *return decrypted number
    */
    BigInt DecodeByPr(const BigInt& c)
    {
        return c.Moden(_d, _N);
    }

    /**
    *encrypt the number
    *m(in): number need to encrypt
    *return encrypted number
    */
    BigInt EncryptByPr(const BigInt& m)
    {
        return DecodeByPr(m);
    }

    /**
    *decrypt the number
    *c(in): number need to decrypt
    *return decrypted number
    */
    BigInt DecodeByPu(const BigInt& c)
    {
        return EncryptByPu(c);
    }

private:
    BigInt CreateRandomOddNum(unsigned int n)
    {
        n = n / 4;
        static unsigned char hex_table[] = { '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' };
        if (n) {
            while (1) {
                std::ostringstream oss;
                for (std::size_t i = 0; i < n - 1; ++i) {
                    oss << hex_table[rand() % 16];
                }
                oss << hex_table[1];
                std::string str(oss.str());
                BigInt r(str);
                if (BigInt(2) <= r) {
                    return r;
                }
            }
        }
        return BigInt::Zero();
    }

    bool IsPrime(const BigInt& n, const unsigned int k)
    {
        if (n == BigInt::Two()) {
            return true;
        }

        if (n == BigInt::Three()) {
            return true;
        }

        BigInt n_1(n - 1);
        BigInt::bit b(n_1);
        if (b.at(0) == 1) {
            return false;
        }

        if ((n % 6 != 1) && (n % 6 != 5)) {
            return false;
        }

        for (std::size_t t = 0; t < k; ++t) {
            BigInt a(CreateRandomSmallThan(n_1));
            BigInt d(BigInt::One());
            for (int i = b.size() - 1; i >= 0; --i) {
                BigInt x(d);
                d *= d;
                d %= n;
                if (d == BigInt::One() && x != BigInt::One() && x != n_1) {
                    return false;
                }
                if (b.at(i)) {
                    d *= a;
                    d %= n;
                }
            }
            if (d != BigInt::One()) {
                return false;
            }
        }
        return true;
    }

    BigInt CreatePrime(unsigned int n, int it_count)
    {
        BigInt res = CreateRandomOddNum(n);
        while (!IsPrime(res, it_count)) {
            res += BigInt::Two();
        }
        return res;
    }

    void MakePrivateKey(const BigInt& ou)
    {
        _d = std::move(_e.ExtendEuclid(ou));
    }

    BigInt CreateRandomSmallThan(const BigInt& a)
    {
        unsigned long t = 0;
        do {
            t = rand();
        } while (t == 0);

        BigInt r = std::move(std::move(BigInt(t)) % a);
        if (r == BigInt::Zero()) {
            r = a - BigInt::One();
        }
        return r;
    }

    friend std::ostream& operator <<(std::ostream& out, const RSA& rsa)//Êä³ö
    {
        out << "N:" << rsa._N << "\n";
        out << "e:" << rsa._e << "\n";
        out << "d:" << rsa._d;
        return out;
    }

private:
    BigInt _e; //public key
    BigInt _d; //private key
    BigInt _N; //public info
};

#endif