#include "StringHelper.h"
#include <cctype>
#if defined(_MSC_VER)
#include <windows.h>
#elif defined(__GNUC__)
#include <iconv.h> 
#else
#error unsupported compiler
#endif

#ifdef min
#undef min
#endif // min
#ifdef max
#undef max
#endif // min

std::string& StringHelper::trim(std::string &s)
{
    return ltrim(rtrim(s));
}

std::string& StringHelper::rtrim(std::string &s)
{
    if (s.empty())  return s;

    return s.erase(s.find_last_not_of(" ") + 1);
}

std::string& StringHelper::ltrim(std::string &s)
{
    if (s.empty())  return s;

    return s.erase(0, s.find_first_not_of(" "));
}

std::vector<std::string> StringHelper::split(const std::string& s, const std::string& delim)
{
    std::vector<std::string> elems;
    size_t pos = 0;
    size_t len = s.length();
    size_t delim_len = delim.length();

    if (!len) return elems;

    if (!delim_len)
    {
        elems.push_back(s);
        return elems;
    }

    while (pos <= len)
    {
        auto find_pos = s.find(delim, pos);
        if (find_pos == std::string::npos)
        {
            elems.push_back(s.substr(pos, len - pos));
            break;
        }
        elems.push_back(s.substr(pos, find_pos - pos));
        pos = find_pos + delim_len;
    }
    return elems;
}

std::string StringHelper::replace(const std::string& str, const std::string& src, const std::string& dest)
{
    std::string result;
    auto str_len = str.length();
    auto src_len = src.length();
    std::string::size_type pos_begin = 0;
    std::string::size_type pos = str.find(src);

    while (pos!=std::string::npos && pos_begin<str_len)
    {
        result.append(str.data() + pos_begin, pos - pos_begin);
        result += dest;
        pos_begin = pos + std::max(src_len, (size_t)1);
        pos = str.find(src, pos_begin);
    }
    if (pos_begin < str_len)
    {
        result.append(str.begin() + pos_begin, str.end());
    }
    return result;
}

std::wstring StringHelper::towchar(const std::string &str, const char *locale)
{
    std::wstring result;
    if (str.empty()) return result;
    size_t str_len = str.length();
    wchar_t *buf = NULL;
    std::string cur_locale;
    if (locale)
    {
        cur_locale = setlocale(LC_CTYPE, NULL);
        setlocale(LC_CTYPE, locale);
    }
    do
    {
#if defined(_MSC_VER)
        buf = new (std::nothrow) wchar_t[str_len + 1];
        if (buf == NULL) break;
        size_t converted = 0;
        auto error = mbstowcs_s(&converted, buf, str_len + 1, str.c_str(), (size_t)-1);
        if (error) break;
#elif defined(__GNUC__)
        auto need_len = mbstowcs(NULL, str.c_str(), 0);
        if (need_len == -1) break;
        buf = new (std::nothrow) wchar_t[need_len + 1];
        if (buf == NULL) break;
        auto use_len = mbstowcs(buf, str.c_str(), need_len + 1);
        if (use_len == -1) break;
#else
#error unsupported compiler
#endif
        result = buf;
    } while (0);
    if (!cur_locale.empty())
    {
        setlocale(LC_CTYPE, cur_locale.c_str());
    }
    if (buf)
    {
        delete[] buf;
    }
    return result;
}

std::string StringHelper::tochar(const std::wstring &wstr, const char *locale)
{
    std::string result;
    if (wstr.empty()) return result;
    size_t wstr_len = wstr.length();
    char *buf = NULL;
    std::string cur_locale;
    if (locale)
    {
        cur_locale = setlocale(LC_CTYPE, NULL);
        setlocale(LC_CTYPE, locale);
    }
    do
    {
#if defined(_MSC_VER)
        buf = new (std::nothrow) char[wstr_len * sizeof(wchar_t) + 1];
        if (buf == NULL) break;
        size_t converted = 0;
        auto error = wcstombs_s(&converted, buf, wstr_len * sizeof(wchar_t) + 1, wstr.c_str(), (size_t)-1);
        if (error) break;
#elif defined(__GNUC__)
        auto need_len = wcstombs(NULL, wstr.c_str(), 0);
        if (need_len == -1) break;
        buf = new (std::nothrow) char[need_len + 1];
        if (buf == NULL) break;
        auto use_len = wcstombs(buf, wstr.c_str(), need_len + 1);
        if (use_len == -1) break;
#else
#error unsupported compiler
#endif
        result = buf;
    } while (0);
    if (!cur_locale.empty())
    {
        setlocale(LC_CTYPE, cur_locale.c_str());
    }
    if (buf)
    {
        delete[] buf;
    }
    return result;
}

std::wstring StringHelper::utf8towchar(const std::string &str_utf8)
{
    if (str_utf8.empty()) return L"";
#if defined(_MSC_VER)
    wchar_t *buf = NULL;
    u_int nLen = MultiByteToWideChar(CP_UTF8, 0, str_utf8.c_str(), str_utf8.size(), NULL, 0);
    if (nLen <= 0)
    {
        return L"";
    }
    buf = new (std::nothrow) wchar_t[nLen];
    if (buf == NULL)
    {
        return L"";
    }
    u_int nRtn = MultiByteToWideChar(CP_UTF8, 0, str_utf8.c_str(), str_utf8.size(), buf, nLen);
    if (nRtn != nLen)
    {
        delete[]buf;
        return L"";
    }
    std::wstring result(buf, nRtn);
    delete[]buf;
    return result;
#elif defined(__GNUC__)
    iconv_t cd;
    cd = iconv_open("WCHAR_T", "UTF-8");
    if ((iconv_t)-1 == cd) 
    {
        return L"";
    }
    char* inbuffer = (char *)str_utf8.c_str();
    size_t srcLen = str_utf8.size();
    size_t outLen = str_utf8.size() * sizeof(wchar_t);
    char* outbuff = new (std::nothrow) char[outLen];
    if (outbuff == NULL)
    { 
        iconv_close(cd);
        return L"";
    }
    char *begin = outbuff;
    auto retsize = iconv(cd, (char **)&inbuffer, (size_t *)&srcLen, &outbuff, (size_t *)&outLen);
    iconv_close(cd);
    if ((size_t)-1 == retsize) 
    {
        delete[]begin;
        return L"";
    }
    std::wstring result((wchar_t*)begin, (outbuff-begin)/sizeof(wchar_t));
    delete[]begin;
    return result;
#else
#error unsupported compiler
#endif
}

std::string StringHelper::wchartoutf8(const std::wstring &wstr)
{
    if (wstr.empty()) return "";
#if defined(_MSC_VER)
    char *buf = NULL;
    u_int nLen = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), wstr.size(), NULL, 0, NULL, NULL);
    if (nLen <= 0)
    {
        return "";
    }
    buf = new (std::nothrow) char[nLen];
    if (buf == NULL)
    {
        return "";
    }
    u_int nRtn = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), wstr.size(), buf, nLen, NULL, NULL);
    if (nRtn != nLen)
    {
        delete[]buf;
        return "";
    }
    std::string result(buf, nRtn);
    delete[]buf;
    return result;
#elif defined(__GNUC__)
    iconv_t cd;
    cd = iconv_open("UTF-8//TRANSLIT", "WCHAR_T");
    if ((iconv_t)-1 == cd)
    {
        return "";
    }
    char* inbuffer = (char *)wstr.c_str();
    size_t srcLen = wstr.size() * sizeof(wchar_t);
    size_t outLen = srcLen * 4;
    char* outbuff = new (std::nothrow) char[outLen];
    if (outbuff == NULL)
    {
        iconv_close(cd);
        return "";
    }
    char *begin = outbuff;
    auto retsize = iconv(cd, (char **)&inbuffer, (size_t *)&srcLen, &outbuff, (size_t *)&outLen);
    iconv_close(cd);
    if ((size_t)-1 == retsize)
    {
        delete[]begin;
        return "";
    }
    std::string result(begin, outbuff-begin);
    delete[]begin;
    return result;
#else
#error unsupported compiler
#endif
}

bool StringHelper::hex2byte(const std::string& hex, char *out, const size_t &out_size)
{
    if (!out) return false;
    out[0] = 0;
    const auto len = hex.length();
    if (hex.empty()) return true;
    if (len & 0X01) return false;
    if ((len >> 1) > out_size) return false;
    for (size_t pos = 0; pos < len; pos += 2)
    {
        if (!isxdigit(hex[pos]) || !isxdigit(hex[pos + 1])) return false;
        out[pos >> 1] = (HEX_STR_TO_NUM(hex[pos]) << 4) | HEX_STR_TO_NUM(hex[pos + 1]);
    }
    return true;
}

std::string StringHelper::byte2basestr(const unsigned char* byte, const size_t &byte_size, const std::string &delim, const io_base base, const size_t width, const char fill, bool upcase)
{
    if (!byte) return "";
    std::ostringstream oss;
    changebase(oss,base);
    setfill(oss, fill);
    if (upcase) oss << std::uppercase;
    for (size_t i = 0; i < byte_size; i++)
    {
        changewidth(oss, width) << (unsigned int)byte[i];
        if (i < byte_size - 1 && !delim.empty())
            oss << delim;
    }
    return oss.str();
}