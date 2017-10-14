#ifndef BIGINT_H_INCLUDED
#define BIGINT_H_INCLUDED

#include <vector>
#include <algorithm>
#include <iostream>
#include <mutex>
#if defined(_MSC_VER)
#include <resrcpool\ResourcePool.h>
#elif defined(__GNUC__)
#include <resrcpool/ResourcePool.h>
#else
#error unsupported compiler
#endif

#ifndef HEX_STR_TO_NUM
#define HEX_STR_TO_NUM(c) (((0X40&(c))>>6)*9+(0X0F&(c))) //you must make sure the c is hex str
#endif // !HEX_STR_TO_NUM

#define BIG_INT_MAX_VECTOR_SIZE 2048

class BigInt
{
public:
    typedef unsigned int base_t;
    typedef std::vector<base_t> data_t;
    typedef const std::vector<base_t> const_data_t;
    static const int base_char = 8;
    static const int base = 0xFFFFFFFF;
    static const int basebitnum = sizeof(base_t) * 8;
    static const int basebitchar = 0x1F;
    static const int basebit = 5;

    class bit
    {
    public:
        bit(const BigInt& ba) : _size(0)
        {
            _bitvec = GetPool().GetResource();
            if (_bitvec->Get().capacity() != GetMaxVectorSize()) {
                _bitvec->Get().reserve(GetMaxVectorSize());
            }
            _bitvec->Get().insert(_bitvec->Get().begin(), ba._data->Get().begin(), ba._data->Get().end());
            if (_bitvec->Get().size()) {
                BigInt::base_t a = _bitvec->Get()[_bitvec->Get().size() - 1];
                _size = _bitvec->Get().size() << (BigInt::basebit);
                BigInt::base_t t = 1 << (BigInt::basebitnum - 1);
                if (a == 0) {
                    _size -= (BigInt::basebitnum);
                }
                else {
                    while (!(a&t)) {
                        --_size;
                        t = t >> 1;
                    }
                }
            }
        }

        ~bit()
        {
            _bitvec->Get().clear();
            GetPool().FreeResource(_bitvec);
        }

        size_t size()
        {
            return _size;
        }

        bool at(size_t i)
        {
            size_t index = i >> (BigInt::basebit); //get the bit index
            size_t off = i&(BigInt::basebitchar); //get the bit off
            BigInt::base_t t = _bitvec->Get()[index]; //get the bit value
            return (t&(1 << off)) != 0; //return the bit is 0 or 1
        }
    private:
        Resource<data_t> * _bitvec; //org data
        size_t _size; //valid bit num, not include the high zero bits
    };

public:
    static size_t& GetMaxBigIntBitNum()
    {
        static size_t max_bit_num = BIG_INT_MAX_VECTOR_SIZE;
        return max_bit_num;
    }

    static void SetMaxBigIntBitNum(size_t max_bit_num)
    {
        GetMaxBigIntBitNum() = max_bit_num * 2;
    }

    static ResourcePool<data_t> &GetPool()
    {
        static ResourcePool<data_t> pool;
        return pool;
    }

public:
    static BigInt& Zero()
    {
        static BigInt Zero(0);
        return Zero;
    }

    static BigInt& One()
    {
        static BigInt One(1);
        return One;

    }

    static BigInt& Two()
    {
        static BigInt Two(2);
        return Two;
    }

    static BigInt& Three()
    {
        static BigInt Three(3);
        return Three;
    }

    /**
    * use polynomial to get the quotients and remainders
    *a(in): the divisor
    *b(in): the dividend
    *quot(out): quotients
    *remainder(out): remainder
    */
    static void Div(const BigInt& a, const BigInt& b, BigInt& quot, BigInt& remainder, bool need_quot = true)
    {
        if (need_quot) {
            quot = 0;
        }
        remainder = 0;
        if (b.Equals(BigInt::Zero())) {
            return;
        }
        if (a.Equals(BigInt::Zero())) {
            return;
        }
        if (b.Equals(BigInt::One())) {
            if (need_quot) {
                quot = a;
                quot._isnegative = (a._isnegative != b._isnegative);
            }
            return;
        }
        if (a.SmallThan(b)) {
            remainder = a;
            return;
        }

        BigInt cb(b);
        cb._isnegative = false;
        remainder._isnegative = false;
        remainder._data->Get().clear();
        remainder._data->Get().insert(remainder._data->Get().begin(), a._data->Get().begin(), a._data->Get().end());

        BigInt::bit bit_b(cb);
        while (true) {
            BigInt::bit bit_a(remainder);
            int len = (int)(bit_a.size() - bit_b.size());
            BigInt temp;
            while (len >= 0) {
                temp = cb << (unsigned int)len;
                if (temp.SmallOrEquals(remainder)) {
                    break;
                }
                --len;
            }
            if (len < 0) {
                break;
            }
            BigInt::base_t n = 0;
            while (temp.SmallOrEquals(remainder)) {
                remainder.Sub(temp);
                ++n;
            }
            BigInt kk(n);
            if (len) {
                kk.LeftShift((unsigned int)len);
            }
            if (need_quot) {
                quot.Add(kk);
            }
        }
        if (need_quot) {
            quot.Trim();
            if (!quot.Equals(Zero())) {
                quot._isnegative = a._isnegative != b._isnegative;
            }
        }
        remainder._isnegative = a._isnegative;
    }

private:
    static size_t GetMaxVectorSize()
    {
        size_t size = GetMaxBigIntBitNum() / sizeof(base_t);
        return size == 0 ? BIG_INT_MAX_VECTOR_SIZE / sizeof(base_t) : size;
    }

public:
    friend BigInt operator + (const BigInt& a, const BigInt& b)
    {
        BigInt ca(a);
        return ca.Add(b);
    }

    friend BigInt& operator += (BigInt& a, const BigInt& b)
    {
        return a.Add(b);
    }

    friend BigInt operator - (const BigInt& a, const BigInt& b)
    {
        BigInt ca(a);
        return ca.Sub(b);
    }

    friend BigInt& operator -= (BigInt& a, const BigInt& b)
    {
        return a.Sub(b);
    }

    friend BigInt operator * (const BigInt& a, const BigInt& b)
    {
        BigInt ca(a);
        return ca.Multi(b);
    }

    friend BigInt& operator *= (BigInt& a, const BigInt& b)
    {
        return a.Multi(b);
    }

    friend BigInt operator / (const BigInt& a, const BigInt& b)
    {
        if (a.Equals(b)) {
            return (a._isnegative == b._isnegative) ? BigInt(1) : BigInt(-1);
        }
        else if (a.SmallThan(b)) {
            return BigInt::Zero();
        }
        else if (b.Equals(BigInt::Zero())) {
            return BigInt::Zero();
        }

        BigInt result, ca;
        BigInt::Div(a, b, result, ca);
        return result;
    }

    friend BigInt& operator /= (BigInt& a, const BigInt& b)
    {
        a = a / b;
        return a;
    }

    friend BigInt operator % (const BigInt& a, const BigInt& b)
    {
        if (a.Equals(b)) {
            return BigInt::Zero();
        }
        else if (a.SmallThan(b)) {
            return a;
        }
        else if (b.Equals(BigInt::Zero())) {
            return BigInt::Zero();
        }

        BigInt result, ca;
        BigInt::Div(a, b, result, ca, false);
        return ca;
    }

    friend BigInt& operator %= (BigInt& a, const BigInt& b)
    {
        a = a % b;
        return a;
    }

    friend bool operator < (const BigInt& a, const BigInt& b)
    {
        if (a._isnegative == b._isnegative) {
            if (a._isnegative == false) {
                return a.SmallThan(b);
            }
            return !(a.SmallOrEquals(b));
        }

        if (a._isnegative == false) {
            return false;
        }
        return true;
    }

    friend bool operator > (const BigInt& a, const BigInt& b)
    {
        return b < a;
    }

    friend bool operator <= (const BigInt& a, const BigInt& b)
    {
        if (a._isnegative == b._isnegative) {
            if (a._isnegative == false) {
                return a.SmallOrEquals(b);
            }
            return !(a.SmallThan(b));
        }
        if (a._isnegative == false) {
            return false;
        }
        return true;
    }

    friend bool operator >= (const BigInt& a, const BigInt& b)
    {
        return b <= a;
    }

    friend bool operator == (const BigInt& a, const BigInt& b)
    {
        return a._isnegative == b._isnegative && a._data->Get() == b._data->Get();
    }

    friend bool operator != (const BigInt& a, const BigInt& b)
    {
        return !(a == b);
    }

    friend BigInt operator + (const BigInt& a, const long b)
    {
        BigInt t(b);
        return a + t;
    }

    friend BigInt& operator += (BigInt& a, const long b)
    {
        BigInt t(b);
        return a += t;
    }

    friend BigInt operator - (const BigInt& a, const long b)
    {
        BigInt t(b);
        return a - t;
    }

    friend BigInt& operator -= (BigInt& a, const long b)
    {
        BigInt t(b);
        return a -= t;
    }

    friend BigInt operator * (const BigInt& a, const long b)
    {
        BigInt t(b);
        return a*t;
    }

    friend BigInt& operator *= (BigInt& a, const long b)
    {
        BigInt t(b);
        return a *= t;
    }

    friend BigInt operator / (const BigInt& a, const long b)
    {
        BigInt t(b);
        return a / t;
    }

    friend BigInt& operator /= (BigInt& a, const long b)
    {
        BigInt t(b);
        return a /= t;
    }

    friend BigInt operator % (const BigInt& a, const long b)
    {
        BigInt t(b);
        return a%t;
    }

    friend BigInt& operator %= (BigInt& a, const long b)
    {
        BigInt t(b);
        return a %= t;
    }

    friend bool operator < (const BigInt& a, const long b)
    {
        BigInt t(b);
        return a < t;
    }

    friend bool operator > (const BigInt& a, const long b)
    {
        BigInt t(b);
        return t < b;
    }

    friend bool operator <= (const BigInt& a, const  long b)
    {
        BigInt t(b);
        return a <= t;
    }

    friend bool operator >= (const BigInt& a, const  long b)
    {
        BigInt t(b);
        return t <= a;
    }

    friend bool operator == (const BigInt& a, const long b)
    {
        BigInt t(b);
        return a == t;
    }

    friend bool operator != (const BigInt& a, const long b)
    {
        BigInt t(b);
        return !(a == t);
    }

    friend BigInt operator << (const BigInt& a, unsigned int n)
    {
        static BigInt ca;
        static std::mutex lock;
        std::unique_lock<std::mutex> lck(lock);
        ca = a;
        return ca.LeftShift(n);
    }

    friend BigInt& operator <<= (BigInt& a, unsigned int n)
    {
        return a.LeftShift(n);
    }

    friend BigInt operator >> (const BigInt& a, unsigned int n)
    {
        static BigInt ca;
        static std::mutex lock;
        std::unique_lock<std::mutex> lck(lock);
        ca = a;
        return ca.RightShift(n);
    }

    friend BigInt& operator >>= (BigInt& a, unsigned int n)
    {
        return a.RightShift(n);
    }

    friend std::ostream& operator << (std::ostream& out, const BigInt& a)
    {
        static char hex[] = { '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' };
        if (a._isnegative) {
            out << "-";
        }
        BigInt::base_t T = 0x0F;
        std::string str;
        for (BigInt::data_t::const_iterator it = a._data->Get().begin(); it != a._data->Get().end(); ++it) {
            BigInt::base_t ch = (*it);
            for (int j = 0; j < BigInt::base_char; ++j) {
                str.insert(str.begin(), hex[ch&(T)]);
                ch = ch >> 4;
            }
        }
        out << str.c_str();
        return out;
    }

public:
    BigInt() :_isnegative(false)
    {
        _data = GetPool().GetResource();
        if (_data->Get().capacity() != GetMaxVectorSize()) {
            _data->Get().reserve(GetMaxVectorSize());
        }
        _data->Get().push_back(0);
    }

    BigInt(const int n) :_isnegative(false)
    {
        _data = GetPool().GetResource();
        if (_data->Get().capacity() != GetMaxVectorSize()) {
            _data->Get().reserve(GetMaxVectorSize());
        }
        InitFromInt(n);
    }

    BigInt(const char *num) :_isnegative(false)
    {
        _data = GetPool().GetResource();
        if (_data->Get().capacity() != GetMaxVectorSize()) {
            _data->Get().reserve(GetMaxVectorSize());
        }
        if (num) {
            InitFromHexString(num);
        }
        else {
            _data->Get().push_back(0);
        }
    }

    BigInt(const std::string& num) :_isnegative(false)
    {
        _data = GetPool().GetResource();
        if (_data->Get().capacity() != GetMaxVectorSize()) {
            _data->Get().reserve(GetMaxVectorSize());
        }
        InitFromHexString(num);
    }

    BigInt(const_data_t data) : _isnegative(false)
    {
        _data = GetPool().GetResource();
        if (_data->Get().capacity() != GetMaxVectorSize()) {
            _data->Get().reserve(GetMaxVectorSize());
        }
        _data->Get().insert(_data->Get().begin(), data.begin(), data.end());
        Trim();
    }

    BigInt(const BigInt& a) : _isnegative(a._isnegative)
    {
        _data = GetPool().GetResource();
        if (_data->Get().capacity() != GetMaxVectorSize()) {
            _data->Get().reserve(GetMaxVectorSize());
        }
        _data->Get().insert(_data->Get().begin(), a._data->Get().begin(), a._data->Get().end());
    }


    BigInt(BigInt&& a) : _isnegative(a._isnegative)
    {
        _data = a._data;
        a._data = NULL;
    }

    ~BigInt()
    {
        if (_data) {
            _data->Get().clear();
            GetPool().FreeResource(_data);
        }
    }

    BigInt& operator =(const int n)
    {
        InitFromInt(n);
        return *this;
    }

    BigInt& operator =(const std::string &s)
    {
        InitFromHexString(s);
        return *this;
    }

    BigInt& operator =(const char *s)
    {
        if (s) {
            InitFromHexString(s);
        }
        return *this;
    }

    BigInt& operator =(const BigInt& a)
    {
        if (this != &a) {
            _data->Get().clear();
            _data->Get().insert(_data->Get().begin(), a._data->Get().begin(), a._data->Get().end());
            _isnegative = a._isnegative;
        }
        return *this;
    }

    BigInt& operator =(BigInt&& a)
    {
        if (this != &a) {
            if (_data) {
                _data->Get().clear();
                GetPool().FreeResource(_data);
                _data = NULL;
            }
            _data = a._data;
            _isnegative = a._isnegative;
            a._data = NULL;
        }
        return *this;
    }

public:
    BigInt Moden(const BigInt& exp, const BigInt& p) const
    {
        BigInt::bit t(exp);

        BigInt d(1);
        for (int i = (int)t.size() - 1; i >= 0; --i) {
            d = (d*d) % p;
            if (t.at(i)) {
                d = (d*(*this)) % p;
            }
        }
        return d;
    }

    BigInt ExtendEuclid(const BigInt& m) const
    {
        if (m._isnegative == true) {
            return BigInt::Zero();
        }
        if (m == BigInt::Zero()) {
            return BigInt::Zero();
        }
        BigInt a[3], b[3], t[3];
        a[0] = 1; a[1] = 0; a[2] = m;
        b[0] = 0; b[1] = 1; b[2] = *this;
        if (b[2] == BigInt::Zero() || b[2] == BigInt::One()) {
            return b[2];
        }

        while (true) {
            if (b[2] == BigInt::One()) {
                if (b[1]._isnegative == true) {
                    b[1] = (b[1] % m + m) % m;
                }
                return b[1];
            }

            BigInt q = a[2] / b[2];
            for (int i = 0; i < 3; ++i) {
                t[i] = a[i] - q * b[i];
                a[i] = b[i];
                b[i] = t[i];
            }
        }
    }

private:
    void InitFromInt(const int n)
    {
        _data->Get().clear();
        _isnegative = false;
        int a = n;
        if (a < 0) {
            _isnegative = true;
            a = -a;
        }
        BigInt::base_t ch = (a&(BigInt::base));
        _data->Get().push_back(ch);
    }

    void InitFromHexString(const std::string& s)
    {
        _data->Get().clear();
        _isnegative = false;
        const char *p = s.c_str();
        size_t len = s.size();

        if (len && p[0] == '-') {
            if (len > 1) {
                _isnegative = true;
            }
            p++;
            len--;
        }

        for (size_t i = 0; i < len;) {
            base_t sum = 0;
            size_t pos = i;
            int off = (len - pos) % base_char;
            for (int j = 0; j < (off ? off : base_char); ++j, ++i) {
                char ch = p[pos + j];
                if (!isxdigit(ch)) {
                    continue;
                }
                ch = HEX_STR_TO_NUM(ch);
                sum = ((sum << 4) | (ch));
            }
            _data->Get().insert(_data->Get().begin(), sum);
        }
        Trim();
    }

    BigInt& Trim()
    {
        int count = 0;
        for (data_t::reverse_iterator it = _data->Get().rbegin(); it != _data->Get().rend(); ++it) {
            if ((*it) == 0) {
                ++count;
            }
            else {
                break;
            }
        }

        if (count == _data->Get().size()) {
            --count;
        }
        for (int i = 0; i < count; ++i) {
            _data->Get().pop_back();
        }
        return *this;
    }

    bool SmallThan(const BigInt& b) const
    {
        if (_data->Get().size() == b._data->Get().size())
        {
            for (BigInt::data_t::const_reverse_iterator it = _data->Get().rbegin(), it_b = b._data->Get().rbegin(); it != _data->Get().rend(); ++it, ++it_b) {
                if ((*it) != (*it_b)) {
                    return (*it) < (*it_b);
                }
            }
            return false;
        }
        return _data->Get().size() < b._data->Get().size();
    }

    bool SmallOrEquals(const BigInt& b) const
    {
        if (_data->Get().size() == b._data->Get().size())
        {
            for (BigInt::data_t::const_reverse_iterator it = _data->Get().rbegin(), it_b = b._data->Get().rbegin(); it != _data->Get().rend(); ++it, ++it_b) {
                if ((*it) != (*it_b)) {
                    return (*it) < (*it_b);
                }
            }
            return true;
        }
        return _data->Get().size() < b._data->Get().size();
    }

    bool Equals(const BigInt& a) const
    {
        return _data->Get() == a._data->Get();
    }

    BigInt& LeftShift(const unsigned int n)
    {
        int k = n >> (BigInt::basebit);
        int off = n&(BigInt::basebitchar);
        int inc = (off == 0) ? k : 1 + k;
        for (int i = 0; i < inc; ++i) {
            _data->Get().push_back(0); //placehold
        }

        if (k) {
            inc = (off == 0) ? 1 : 2;
            for (int i = (int)_data->Get().size() - inc; i >= k; --i) {
                _data->Get()[i] = _data->Get()[i - k];
            }
            for (int i = 0; i < k; ++i) {
                _data->Get()[i] = 0;
            }
        }

        if (off) {
            BigInt::base_t T = BigInt::base;//0xffffffff
            T = T << (BigInt::basebitnum - off);//32
            BigInt::base_t ch = 0;
            for (std::size_t i = k; i < _data->Get().size(); ++i) {
                BigInt::base_t t = _data->Get()[i];
                _data->Get()[i] = (t << off) | ch;
                ch = (t&T) >> (BigInt::basebitnum - off);//32
            }
        }
        Trim();
        return *this;
    }

    BigInt& RightShift(const unsigned int n)
    {
        if (n >= BigInt::bit(*this).size()) {
            *this = Zero();
            return *this;
        }

        int k = n >> (BigInt::basebit);
        int off = n&(BigInt::basebitchar);

        if (k) {
            for (int i = 0; i < k; ++i) {
                if ((size_t)(i + k) < _data->Get().size()) {
                    _data->Get()[i] = _data->Get()[i + k];
                }
                else {
                    _data->Get()[i] = 0;
                }
            }
            for (int i = 0; i<k && !_data->Get().empty(); ++i) {
                _data->Get().pop_back();
            }
            if (_data->Get().size() == 0) {
                _data->Get().push_back(0);
            }
        }

        if (off) {
            BigInt::base_t T = BigInt::base;//0xFFFFFFFF
            T = T >> (BigInt::basebitnum - off);//32
            BigInt::base_t ch = 0;
            for (int i = (int)_data->Get().size() - 1; i >= 0; --i) {
                BigInt::base_t t = _data->Get()[i];
                _data->Get()[i] = (t >> off) | ch;
                ch = (t&T) << (BigInt::basebitnum - off);//32
            }
        }
        Trim();
        return *this;
    }

    BigInt& Add(const BigInt& b)
    {
        if (b == (BigInt::Zero())) {
            return *this;
        }

        if (*this == (BigInt::Zero())) {
            *this = b;
            return *this;
        }

        if (_isnegative == b._isnegative) {
            BigInt::data_t &res = _data->Get();
            int len = (int)(b._data->Get().size() - _data->Get().size());
            while ((len--) > 0) {
                res.push_back(0);
            }

            int cn = 0;
            for (std::size_t i = 0; i < b._data->Get().size(); ++i) {
                BigInt::base_t temp = res[i];
                res[i] = res[i] + b._data->Get()[i] + cn;
                cn = temp > res[i] ? 1 : temp > (temp + b._data->Get()[i]) ? 1 : 0;//0xFFFFFFFF
            }

            for (std::size_t i = b._data->Get().size(); i < _data->Get().size() && cn != 0; ++i) {
                BigInt::base_t temp = res[i];
                res[i] = (res[i] + cn);
                cn = temp > res[i];
            }

            if (cn != 0) {
                res.push_back(cn);
            }
            Trim();
        }
        else {
            bool isnegative;
            if (SmallThan(b)) {
                isnegative = b._isnegative;
            }
            else if (Equals(b)) {
                isnegative = false;
            }
            else {
                isnegative = _isnegative;
            }
            _isnegative = b._isnegative;
            Sub(b);
            _isnegative = isnegative;
        }
        return *this;
    }

    BigInt& Sub(const BigInt& b)
    {
        if (b == (BigInt::Zero())) {
            return *this;
        }

        if (*this == (BigInt::Zero())) {
            *this = b;
            this->_isnegative = !this->_isnegative;
            return *this;
        }

        if (b._isnegative == _isnegative) {
            BigInt::data_t &res = _data->Get();
            if (!(SmallThan(b))) {
                BigInt::base_t cn = 0;
                for (size_t i = 0; i < b._data->Get().size(); ++i) {
                    BigInt::base_t temp = res[i];
                    res[i] = (res[i] - b._data->Get()[i] - cn);
                    cn = temp < res[i] ? 1 : temp < b._data->Get()[i] ? 1 : 0;
                }
                for (size_t i = b._data->Get().size(); i < _data->Get().size() && cn != 0; ++i) {
                    BigInt::base_t temp = res[i];
                    res[i] = res[i] - cn;
                    cn = temp < cn;
                }
                Trim();
            }
            else {
                data_t tmp = (b - (*this))._data->Get();
                _data->Get().clear();
                _data->Get().insert(_data->Get().begin(), tmp.begin(), tmp.end());
                _isnegative = !_isnegative;
            }
        }
        else {
            bool isnegative = _isnegative;
            _isnegative = b._isnegative;
            Add(b);
            _isnegative = isnegative;
        }
        return *this;
    }

    BigInt& Multi(const BigInt& b)
    {
        if (*this == (BigInt::Zero())) {
            return *this;
        }

        if (b == (BigInt::Zero())) {
            *this = b;
            return *this;
        }

        if (b.Equals(BigInt::One())) {
            this->_isnegative = this->_isnegative != b._isnegative;
            return *this;
        }

        if (this->Equals(BigInt::One())) {
            bool isnegative = this->_isnegative != b._isnegative;
            *this = b;
            this->_isnegative = isnegative;
            return *this;
        }

        BigInt big_num;
        BigInt small_num;
        if (_data->Get().size() > b._data->Get().size()) {
            big_num = *this;
            small_num = b;
        }
        else {
            big_num = b;
            small_num = *this;
        }
        bool org_negative = _isnegative;
        *this = BigInt::Zero();
        BigInt::bit bt(small_num);
        for (int i = (int)bt.size() - 1; i >= 0; --i) {
            if (bt.at(i)) {
                BigInt temp(big_num);
                temp._isnegative = false;
                temp.LeftShift((unsigned int)i);
                Add(temp);
            }
        }
        _isnegative = !(org_negative == b._isnegative);
        return *this;
    }

private:
    Resource<data_t> *_data; //data store in little endian, low index store low octet
    bool _isnegative; // is negative
};

#endif