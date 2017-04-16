#ifndef STRING_HELPER_H_INCLUDED
#define STRING_HELPER_H_INCLUDED

#include <string>
#include <vector>
#ifdef min
#undef min
#endif // min
#include <algorithm>
#include <stdlib.h>
#include <iomanip>
#include <sstream>

#define HEX_STR_TO_NUM(c) (((0X40&(c))>>6)*9+(0X0F&(c))) //you must make sure the c is hex str

class StringHelper
{
public:
    enum io_base
    {
        hex = 0,
        oct = 1,
        dec = 2,
    };
public:
    /**
    *remove the blank at both end of the string
    *s(in): the string that you want to rm the blank
    */
    static std::string& trim(std::string &s);
    /**
    *remove the blank at right end of the string
    *s(in): the string that you want to rm the blank at right end
    */
    static std::string& rtrim(std::string &s);
    /**
    *remove the blank at left end of the string
    *s(in): the string that you want to rm the blank at left end
    */
    static std::string& ltrim(std::string &s);
    /**
    *split the string with the delim
    *s(in): the string you want to split with the delim
    *delim(in): the delim that you want to use to split the string
    */
    static std::vector<std::string> split(const std::string& s, const std::string& delim);
    /**
    *connect the ele in vec with the connector
    *vec(in): the set you want deal to join them together
    *connector(in), the connector that you want to use to join the set
    */
    template<typename T>
    static std::string join(const std::vector<T>& vec, const std::string &connector)
    {
        std::string result;
        if (vec.size() == 0)
        {
            return result;
        }

        auto cur = vec.begin();
        auto next = cur + 1;
        for (; next != vec.end(); cur = next, ++next)
        {
            result += *cur + connector;
        }
        result += *cur;
        return result;
    }

    /**
    *replace the substr in the str with dest, if you input src is empty, it will replace ervery character with the dest
    *str(in): the str that you want to replace substr
    *src(in): the substr that you want to replace
    *dest(in): the substr that you want to replace with
    */
    static std::string replace(const std::string& str, const std::string& src, const std::string& dest);

    /**
    *upcase the string
    *str(in): the string that you want to deal
    */
    static std::string& toupper(std::string &str)
    {
        std::transform(str.begin(), str.end(), str.begin(), ::toupper);
        return str;
    }
    /**
    *upcase the string
    *str(in): the string that you want to deal
    */
    static std::string&& toupper(std::string &&str)
    {
        std::transform(str.begin(), str.end(), str.begin(), ::toupper);
        return std::move(str);
    }
    /**
    *upcase the string
    *str(in): the string that you want to deal
    */
    static std::string toupper(const std::string &str)
    {
        std::string result = str;
        std::transform(result.begin(), result.end(), result.begin(), ::toupper);
        return result;
    }
    /**
    *lowcase the string
    *str(in): the string that you want to deal
    */
    static std::string& tolower(std::string &str)
    {
        std::transform(str.begin(), str.end(), str.begin(), ::tolower);
        return str;
    }
    /**
    *lowcase the string
    *str(in): the string that you want to deal
    */
    static std::string&& tolower(std::string &&str)
    {
        std::transform(str.begin(), str.end(), str.begin(), ::tolower);
        return std::move(str);
    }
    /**
    *lowcase the string
    *str(in): the string that you want to deal
    */
    static std::string tolower(const std::string &str)
    {
        std::string result = str;
        std::transform(result.begin(), result.end(), result.begin(), ::tolower);
        return result;
    }
    /**
    *change multi char to wchar, using specify charactor set to convert
    *str(in): the multi need to convert
    *locale(in): the language of the string£¬use it to decode, chinese is windows"chs" linux"zh_CN.UTF-8", english is "C"
    */
    static std::wstring towchar(const std::string &str, const char *locale = NULL);
    /**
    *change wchar to multi char , using specify charactor set to convert
    *wstr(in): the multi need to convert
    *locale(in): the language of the string£¬use it to encode, chinese is "chs", english is "C"
    */
    static std::string tochar(const std::wstring &wstr, const char *locale = NULL);
    /**
    *convert string to other type
    *T1: the type you want to convert to
    *T2: the type you want to be converted, it can be every type that can use operator <<
    *str: the str to be converted
    */
    template<typename T1, typename T2=std::string>
    static T1 convert(const T2 &str)
    {
        T1 value;
        std::stringstream ss;
        ss << str;
        ss >> value;
        return value;
    }
    /**
    *convert the hex string to its mean byte, like string "12" to byte 18(1*16+2)
    *hex(in): the hex string need to convert, can not have 0x prefix, should only have hex string
    *out(out): the byte of the hex string
    *out_size(in): the size of out
    */
    static bool hex2byte(const std::string& hex, char *out, const size_t &out_size);
    /**
    *convert the byte array to base(hex oct dec) string
    *byte(in): the byte need to convert
    *byte_size(in): the num of the byte
    *delim(in): the delim between two bytes, like if byte 18 19 to hex string, delim ":", then hex string is "12:13"
    *io_base(in): the base you want to choose to use, see io_base
    *width(in): the width of the base string
    *fill(in): if the width is not enough, then will use the fill char to fill
    *upcase(in): the hex string should be upcase
    */
    static std::string byte2basestr(const unsigned char* byte, const size_t &byte_size, const std::string &delim = std::string(), const io_base base = hex, const size_t width = 0,const char fill = '0', bool upcase = true);
    
private:
    template<class _Elem,class _Traits>
    static std::basic_ostream<_Elem, _Traits>& changebase(std::basic_ostream<_Elem, _Traits>& ostream, const io_base base)
    {
        switch (base)
        {
        case hex:
            ostream << std::hex;
            return ostream;
        case oct:
            ostream << std::oct;
            return ostream;
        case dec:
            ostream << std::dec;
            return ostream;
        default:
            ostream << std::dec;
            return ostream;
        }
    }

    template<class _Elem, class _Traits>
    static std::basic_ostream<_Elem, _Traits>& changewidth(std::basic_ostream<_Elem, _Traits>& ostream, const size_t width)
    {
        ostream << std::setw(width);
        return ostream;
    }

    template<class _Elem, class _Traits>
    static std::basic_ostream<_Elem, _Traits>& setfill(std::basic_ostream<_Elem, _Traits>& ostream, const char fill)
    {
        ostream << std::setfill(fill);
        return ostream;
    }
};

#endif
