#include "StringHelper.h"
#include "Lang.h"
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

std::mutex StringHelper::char_wchar_lock;
std::map<std::string, std::string> StringHelper::html_charset_to_locale_map = {
    std::pair<std::string, std::string>("US-ASCII", "ISO-IR-6"),
    std::pair<std::string, std::string>("ISO_8859-1", "ISO-IR-100"),
    std::pair<std::string, std::string>("ISO_8859-2", "ISO-IR-101"),
    std::pair<std::string, std::string>("ISO_8859-3", "ISO-IR-109"),
    std::pair<std::string, std::string>("ISO_8859-4", "ISO-IR-110"),
    std::pair<std::string, std::string>("ISO_8859-5", "ISO-IR-144"),
    std::pair<std::string, std::string>("ISO_8859-6", "ISO-IR-127"),
    std::pair<std::string, std::string>("ISO_8859-7", "ISO-IR-126"),
    std::pair<std::string, std::string>("ISO_8859-8", "ISO-IR-138"),
    std::pair<std::string, std::string>("ISO_8859-9", "ISO-IR-148"),
    std::pair<std::string, std::string>("ISO-8859-10", "ISO-IR-157"),
    std::pair<std::string, std::string>("ISO_6937-2-add", "ISO-IR-142"),
    std::pair<std::string, std::string>("BS_4730", "ISO-IR-4"),
    std::pair<std::string, std::string>("SEN_850200_C", "ISO-IR-11"),
    std::pair<std::string, std::string>("IT", "ISO-IR-15"),
    std::pair<std::string, std::string>("ES", "ISO-IR-17"),
    std::pair<std::string, std::string>("DIN_66003", "ISO-IR-21"),
    std::pair<std::string, std::string>("NS_4551-1", "ISO-IR-60"),
    std::pair<std::string, std::string>("NF_Z_62-010", "ISO-IR-69"),
    std::pair<std::string, std::string>("ISO_646.IRV:1983", "ISO-IR-2"),
    std::pair<std::string, std::string>("NATS-SEFI", "ISO-IR-8-1"),
    std::pair<std::string, std::string>("NATS-SEFI-ADD", "ISO-IR-8-2"),
    std::pair<std::string, std::string>("NATS-DANO", "ISO-IR-9-1"),
    std::pair<std::string, std::string>("NATS-DANO-ADD", "ISO-IR-9-2"),
    std::pair<std::string, std::string>("SEN_850200_B", "ISO-IR-10"),
    std::pair<std::string, std::string>("KS_C_5601-1987", "ISO-IR-149"),
    std::pair<std::string, std::string>("JIS_C6220-1969-jp", "ISO-IR-13"),
    std::pair<std::string, std::string>("JIS_C6220-1969-ro", "ISO-IR-14"),
    std::pair<std::string, std::string>("PT", "ISO-IR-16"),
    std::pair<std::string, std::string>("GREEK7-OLD", "ISO-IR-18"),
    std::pair<std::string, std::string>("LATIN-GREEK", "ISO-IR-19"),
    std::pair<std::string, std::string>("NF_Z_62-010_(1973)", "ISO-IR-25"),
    std::pair<std::string, std::string>("LATIN-GREEK-1", "ISO-IR-27"),
    std::pair<std::string, std::string>("ISO_5427", "ISO-IR-37"),
    std::pair<std::string, std::string>("JIS_C6226-1978", "ISO-IR-42"),
    std::pair<std::string, std::string>("BS_VIEWDATA", "ISO-IR-47"),
    std::pair<std::string, std::string>("INIS", "ISO-IR-49"),
    std::pair<std::string, std::string>("INIS-8", "ISO-IR-50"),
    std::pair<std::string, std::string>("INIS-CYRILLIC", "ISO-IR-51"),
    std::pair<std::string, std::string>("ISO_5427:1981", "ISO-IR-54"),
    std::pair<std::string, std::string>("ISO_5428:1980", "ISO-IR-55"),
    std::pair<std::string, std::string>("GB_1988-80", "ISO-IR-57"),
    std::pair<std::string, std::string>("GB_2312-80", "ISO-IR-58"),
    std::pair<std::string, std::string>("NS_4551-2", "ISO-IR-61"),
    std::pair<std::string, std::string>("VIDEOTEX-SUPPL", "ISO-IR-70"),
    std::pair<std::string, std::string>("PT2", "ISO-IR-84"),
    std::pair<std::string, std::string>("ES2", "ISO-IR-85"),
    std::pair<std::string, std::string>("MSZ_7795.3", "ISO-IR-86"),
    std::pair<std::string, std::string>("JIS_C6226-1983", "ISO-IR-87"),
    std::pair<std::string, std::string>("GREEK7", "ISO-IR-88"),
    std::pair<std::string, std::string>("ASMO_449", "ISO-IR-89"),
    std::pair<std::string, std::string>("ISO-IR-90", "ISO-IR-90"),
    std::pair<std::string, std::string>("JIS_C6229-1984-A", "ISO-IR-91"),
    std::pair<std::string, std::string>("JIS_C6229-1984-B", "ISO-IR-92"),
    std::pair<std::string, std::string>("JIS_C6229-1984-B-ADD", "ISO-IR-93"),
    std::pair<std::string, std::string>("JIS_C6229-1984-HAND", "ISO-IR-94"),
    std::pair<std::string, std::string>("JIS_C6229-1984-HAND-ADD", "ISO-IR-95"),
    std::pair<std::string, std::string>("JIS_C6229-1984-KANA", "ISO-IR-96"),
    std::pair<std::string, std::string>("ISO_2033-1983", "ISO-IR-98"),
    std::pair<std::string, std::string>("ANSI_X3.110-1983", "ISO-IR-99"),
    std::pair<std::string, std::string>("T.61-7BIT", "ISO-IR-102"),
    std::pair<std::string, std::string>("T.61-8BIT", "ISO-IR-103"),
    std::pair<std::string, std::string>("ECMA-CYRILLIC", "ISO-IR-111"),
    std::pair<std::string, std::string>("CSA_Z243.4-1985-1", "ISO-IR-121"),
    std::pair<std::string, std::string>("CSA_Z243.4-1985-2", "ISO-IR-122"),
    std::pair<std::string, std::string>("CSA_Z243.4-1985-GR", "ISO-IR-123"),
    std::pair<std::string, std::string>("T.101-G2", "ISO-IR-128"),
    std::pair<std::string, std::string>("CSN_369103", "ISO-IR-139"),
    std::pair<std::string, std::string>("JUS_I.B1.002", "ISO-IR-141"),
    std::pair<std::string, std::string>("IEC_P27-1", "ISO-IR-143"),
    std::pair<std::string, std::string>("JUS_I.B1.003-SERB", "ISO-IR-146"),
    std::pair<std::string, std::string>("JUS_I.B1.003-MAC", "ISO-IR-147"),
    std::pair<std::string, std::string>("GREEK-CCITT", "ISO-IR-150"),
    std::pair<std::string, std::string>("NC_NC00-10:81", "ISO-IR-151"),
    std::pair<std::string, std::string>("ISO_6937-2-25", "ISO-IR-152"),
    std::pair<std::string, std::string>("GOST_19768-74", "ISO-IR-153"),
    std::pair<std::string, std::string>("ISO_8859-SUPP", "ISO-IR-154"),
    std::pair<std::string, std::string>("ISO_10367-BOX", "ISO-IR-155"),
    std::pair<std::string, std::string>("LATIN-LAP", "ISO-IR-158"),
    std::pair<std::string, std::string>("JIS_X0212-1990", "ISO-IR-159"),
    std::pair<std::string, std::string>("JIS_X0212-1990", "ISO-IR-159"),
    std::pair<std::string, std::string>("ISO-8859-14", "ISO-IR-199"),
    std::pair<std::string, std::string>("ISO-8859-16", "ISO-IR-226"),
    std::pair<std::string, std::string>("UNICODE-1-1-UTF-7", LANGUAGE_UTF7),
    std::pair<std::string, std::string>("UTF-8", LANGUAGE_UTF8),
    std::pair<std::string, std::string>("ISO-10646-UCS-2", LANGUAGE_UTF16LE),
    std::pair<std::string, std::string>("ISO-10646-UCS-4", LANGUAGE_UTF32LE),
    std::pair<std::string, std::string>("ISO-10646-UCS-BASIC", LANGUAGE_ASCII),
    std::pair<std::string, std::string>("ISO-10646-J-1", LANGUAGE_UTF16LE),
    std::pair<std::string, std::string>("ISO-Unicode-IBM-1261", LANGUAGE_UTF16LE),
    std::pair<std::string, std::string>("ISO-Unicode-IBM-1268", LANGUAGE_UTF16LE),
    std::pair<std::string, std::string>("ISO-Unicode-IBM-1276", LANGUAGE_UTF16LE),
    std::pair<std::string, std::string>("ISO-Unicode-IBM-1264", LANGUAGE_UTF16LE),
    std::pair<std::string, std::string>("ISO-Unicode-IBM-1265", LANGUAGE_UTF16LE),
    std::pair<std::string, std::string>("UNICODE-1-1", LANGUAGE_UTF16LE),
    std::pair<std::string, std::string>("UTF-7", LANGUAGE_UTF7),
    std::pair<std::string, std::string>("UTF-16BE", LANGUAGE_UTF16BE),
    std::pair<std::string, std::string>("UTF-16LE", LANGUAGE_UTF16LE),
    std::pair<std::string, std::string>("UTF-16", LANGUAGE_UTF16LE),
    std::pair<std::string, std::string>("UTF-32", LANGUAGE_UTF32LE),
    std::pair<std::string, std::string>("UTF-32LE", LANGUAGE_UTF32LE),
    std::pair<std::string, std::string>("UTF-32BE", LANGUAGE_UTF32BE),
    std::pair<std::string, std::string>("GBK", LANGUAGE_CHINESE_SIMPLIFIED),
    std::pair<std::string, std::string>("GB18030", LANGUAGE_CHINESE_SIMPLIFIED),
    std::pair<std::string, std::string>("ISO-8859-1-WINDOWS-3.0-LATIN-1", LANGUAGE_ENGLISH_EUROPE),
    std::pair<std::string, std::string>("ISO-8859-1-WINDOWS-3.1-LATIN-1", LANGUAGE_ENGLISH_EUROPE),
    std::pair<std::string, std::string>("ISO-8859-1-WINDOWS-LATIN-2", LANGUAGE_ENGLISH_EUROPE),
    std::pair<std::string, std::string>("ISO-8859-1-WINDOWS-LATIN-9", LANGUAGE_TURKISH),
    std::pair<std::string, std::string>("IBM850", LANGUAGE_ENGLISH_EUROPE),
    std::pair<std::string, std::string>("PC8-DANISH-NORWEGIAN", LANGUAGE_NORWEGIAN_BOKMAL),
    std::pair<std::string, std::string>("IBM862", LANGUAGE_HEBREW),
    std::pair<std::string, std::string>("PC8-TURKISH", LANGUAGE_TURKISH),
    std::pair<std::string, std::string>("IBM-THAI", LANGUAGE_THAI),
    std::pair<std::string, std::string>("IBM-THAI", LANGUAGE_THAI),
    std::pair<std::string, std::string>("GB2312", LANGUAGE_CHINESE_SIMPLIFIED),
    std::pair<std::string, std::string>("BIG5", LANGUAGE_CHINESE_TRADITIONAL),
    std::pair<std::string, std::string>("MACINTOSH", LANGUAGE_ENGLISH_EUROPE),
    std::pair<std::string, std::string>("IBM037", LANGUAGE_ENGLISH_CANADA),
    std::pair<std::string, std::string>("IBM273", LANGUAGE_GERMAN),
    std::pair<std::string, std::string>("IBM277", LANGUAGE_SAMI_LULE_NORWAY),
    std::pair<std::string, std::string>("IBM278", LANGUAGE_SAMI_LULE_SWEDEN),
    std::pair<std::string, std::string>("IBM280", LANGUAGE_CATALAN_ITALY),
    std::pair<std::string, std::string>("IBM284", LANGUAGE_CATALAN_SPAIN),
    std::pair<std::string, std::string>("IBM285", LANGUAGE_WELSH_UNITED_KINGDOM),
    std::pair<std::string, std::string>("IBM290", LANGUAGE_JAPANESE),
    std::pair<std::string, std::string>("IBM297", LANGUAGE_FRENCH_FRANCE),
    std::pair<std::string, std::string>("IBM420", LANGUAGE_ARABIC),
    std::pair<std::string, std::string>("IBM423", LANGUAGE_GREEK),
    std::pair<std::string, std::string>("IBM424", LANGUAGE_HEBREW),
    std::pair<std::string, std::string>("IBM437", LANGUAGE_ENGLISH_UNITED_STATES),
    std::pair<std::string, std::string>("IBM500", LANGUAGE_ENGLISH_UNITED_STATES),
    std::pair<std::string, std::string>("IBM852", LANGUAGE_ENGLISH_EUROPE),
    std::pair<std::string, std::string>("IBM855", LANGUAGE_OSSETIAN_CYRILLIC_RUSSIA),
    std::pair<std::string, std::string>("IBM857", LANGUAGE_TURKISH),
    std::pair<std::string, std::string>("IBM860", LANGUAGE_PORTUGUESE),
    std::pair<std::string, std::string>("IBM861", LANGUAGE_ICELANDIC),
    std::pair<std::string, std::string>("IBM863", LANGUAGE_FRENCH_CANADA),
    std::pair<std::string, std::string>("IBM864", LANGUAGE_ARABIC),
    std::pair<std::string, std::string>("IBM865", LANGUAGE_ENGLISH_NORFOLK_ISLAND),
    std::pair<std::string, std::string>("IBM869", LANGUAGE_GREEK),
    std::pair<std::string, std::string>("IBM880", LANGUAGE_RUSSIAN),
    std::pair<std::string, std::string>("IBM905", LANGUAGE_TURKISH),
    std::pair<std::string, std::string>("IBM1026", LANGUAGE_TURKISH),
    std::pair<std::string, std::string>("HZ-GB-2312", LANGUAGE_CHINESE_SIMPLIFIED),
    std::pair<std::string, std::string>("KOI8-U", LANGUAGE_UKRAINIAN),
    std::pair<std::string, std::string>("IBM01140", LANGUAGE_ENGLISH_CANADA),
    std::pair<std::string, std::string>("IBM01141", LANGUAGE_ENGLISH_GERMANY),
    std::pair<std::string, std::string>("IBM01143", LANGUAGE_ENGLISH_SWEDEN),
    std::pair<std::string, std::string>("IBM01144", LANGUAGE_CATALAN_ITALY),
    std::pair<std::string, std::string>("IBM01145", LANGUAGE_CATALAN_SPAIN),
    std::pair<std::string, std::string>("IBM01146", LANGUAGE_ENGLISH_UNITED_KINGDOM),
    std::pair<std::string, std::string>("IBM01147", LANGUAGE_CATALAN_FRANCE),
    std::pair<std::string, std::string>("IBM01148", LANGUAGE_ENGLISH_UNITED_STATES),
    std::pair<std::string, std::string>("IBM01149", LANGUAGE_ICELANDIC),
    std::pair<std::string, std::string>("BIG5-HKSCS", LANGUAGE_CHINESE_TRADITIONAL_HONG_KONG_SAR),
    std::pair<std::string, std::string>("CP51932", LANGUAGE_JAPANESE),
    std::pair<std::string, std::string>("WINDOWS-874", LANGUAGE_THAI),
    std::pair<std::string, std::string>("WINDOWS-1250", LANGUAGE_ENGLISH_EUROPE),
    std::pair<std::string, std::string>("WINDOWS-1251", LANGUAGE_RUSSIAN),
    std::pair<std::string, std::string>("WINDOWS-1252", LANGUAGE_ENGLISH_EUROPE),
    std::pair<std::string, std::string>("WINDOWS-1253", LANGUAGE_GREEK),
    std::pair<std::string, std::string>("WINDOWS-1254", LANGUAGE_TURKISH),
    std::pair<std::string, std::string>("WINDOWS-1255", LANGUAGE_HEBREW),
    std::pair<std::string, std::string>("WINDOWS-1256", LANGUAGE_ARABIC),
    std::pair<std::string, std::string>("WINDOWS-1258", LANGUAGE_VIETNAMESE),
    std::pair<std::string, std::string>("CP50220", LANGUAGE_JAPANESE),
    std::pair<std::string, std::string>("EUC-JP", LANGUAGE_JAPANESE),
    std::pair<std::string, std::string>("EXTENDED_UNIX_CODE_FIXED_WIDTH_FOR_JAPANESE", LANGUAGE_JAPANESE),
    std::pair<std::string, std::string>("ISO-2022-KR", LANGUAGE_KOREAN),
    std::pair<std::string, std::string>("EUC-KR", LANGUAGE_KOREAN),
    std::pair<std::string, std::string>("EUC-KR", LANGUAGE_KOREAN),
    std::pair<std::string, std::string>("ISO-2022-JP", LANGUAGE_JAPANESE),
    std::pair<std::string, std::string>("ISO-2022-JP-2", LANGUAGE_JAPANESE),
    std::pair<std::string, std::string>("ISO-2022-CN", LANGUAGE_CHINESE_TRADITIONAL),
    std::pair<std::string, std::string>("ISO-2022-CN-EXT", LANGUAGE_CHINESE_TRADITIONAL),
    std::pair<std::string, std::string>("ISO-8859-13", LANGUAGE_ESTONIAN),
    std::pair<std::string, std::string>("ISO-8859-15", LANGUAGE_ENGLISH_EUROPE),
    std::pair<std::string, std::string>("ISO-8859-15", LANGUAGE_ENGLISH_EUROPE),
    std::pair<std::string, std::string>("SHIFT_JIS", LANGUAGE_JAPANESE),
    std::pair<std::string, std::string>("JIS_X0201", LANGUAGE_JAPANESE),
    std::pair<std::string, std::string>("JIS_ENCODING", LANGUAGE_JAPANESE),
    std::pair<std::string, std::string>("WINDOWS-31J", LANGUAGE_JAPANESE),
    std::pair<std::string, std::string>("DS_2089", LANGUAGE_DANISH),
    std::pair<std::string, std::string>("US-DK", LANGUAGE_ENGLISH_UNITED_STATES),
    std::pair<std::string, std::string>("DK-US", "ISO-IR-150"),
    std::pair<std::string, std::string>("KOI8-R", LANGUAGE_RUSSIAN),
    std::pair<std::string, std::string>("VIQR", LANGUAGE_VIETNAMESE),
    std::pair<std::string, std::string>("VISCII", LANGUAGE_VIETNAMESE),
    std::pair<std::string, std::string>("EBCDIC-AT-DE", LANGUAGE_GERMAN_AUSTRIA),
    std::pair<std::string, std::string>("EBCDIC-AT-DE-A", LANGUAGE_GERMAN_AUSTRIA),
    std::pair<std::string, std::string>("EBCDIC-CA-FR", LANGUAGE_CATALAN_FRANCE),
    std::pair<std::string, std::string>("EBCDIC-DK-NO", LANGUAGE_FAROESE_DENMARK),
    std::pair<std::string, std::string>("EBCDIC-DK-NO-A", LANGUAGE_FAROESE_DENMARK),
    std::pair<std::string, std::string>("EBCDIC-FI-SE", LANGUAGE_SAMI_NORTHERN_FINLAND),
    std::pair<std::string, std::string>("EBCDIC-FI-SE-A", LANGUAGE_SAMI_NORTHERN_FINLAND),
    std::pair<std::string, std::string>("EBCDIC-FR", LANGUAGE_FRENCH),
    std::pair<std::string, std::string>("EBCDIC-IT", LANGUAGE_ITALIAN),
    std::pair<std::string, std::string>("EBCDIC-PT", LANGUAGE_PORTUGUESE),
    std::pair<std::string, std::string>("EBCDIC-ES", LANGUAGE_SPANISH),
    std::pair<std::string, std::string>("EBCDIC-ES-A", LANGUAGE_SPANISH),
    std::pair<std::string, std::string>("EBCDIC-ES-S", LANGUAGE_SPANISH),
    std::pair<std::string, std::string>("EBCDIC-UK", LANGUAGE_UKRAINIAN),
    std::pair<std::string, std::string>("EBCDIC-US", LANGUAGE_ENGLISH),
    std::pair<std::string, std::string>("VENTURA-US", LANGUAGE_ENGLISH),
    std::pair<std::string, std::string>("VENTURA-INTERNATIONAL", LANGUAGE_ENGLISH),
    std::pair<std::string, std::string>("WINDOWS-1257", LANGUAGE_ESTONIAN),
    std::pair<std::string, std::string>("TIS-620", LANGUAGE_THAI),
    std::pair<std::string, std::string>("TSCII", LANGUAGE_TAMIL),
};

std::string StringHelper::trim(const std::string &s)
{
    return ltrim(rtrim(s));
}

std::string& StringHelper::trim(std::string &s)
{
    return ltrim(rtrim(s));
}

std::string StringHelper::rtrim(const std::string &s)
{
    std::string r = s;
    if (r.empty())  return r;

    return r.erase(r.find_last_not_of(" ") + 1);
}

std::string& StringHelper::rtrim(std::string &s)
{
    if (s.empty())  return s;

    return s.erase(s.find_last_not_of(" ") + 1);
}

std::string StringHelper::ltrim(const std::string &s)
{
    std::string r = s;
    if (r.empty())  return r;

    return r.erase(0, r.find_first_not_of(" "));
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

std::string StringHelper::defaultlocale()
{
    std::string r;
#if defined(_MSC_VER)
    wchar_t name[LOCALE_NAME_MAX_LENGTH] = { 0 };
    int ret = GetUserDefaultLocaleName(name, sizeof(name));
    if (ret > 0) {
        r = StringHelper::tochar(name, "en-US");
    }
#elif defined(__GNUC__)
    r = getenv("LANG");
#else
#error unsupported compiler
#endif
    return r;
}

std::wstring StringHelper::towcharbycharset(const std::string &str, const std::string &charset)
{
    std::string locale;
    std::string up_html_charset_to_locale_map = StringHelper::trim(StringHelper::toupper(charset));
    if (html_charset_to_locale_map.find(up_html_charset_to_locale_map) != html_charset_to_locale_map.end()) {
        locale = html_charset_to_locale_map[up_html_charset_to_locale_map];
    }
    else {
        locale = defaultlocale();
    }
    return towchar(str, locale.c_str());
}

std::wstring StringHelper::towchar(const std::string &str, const char *locale)
{
    std::wstring result;
    if (str.empty()) return result;
    size_t str_len = str.length();
    wchar_t *buf = NULL;
    std::string cur_locale;
    std::string default_locale;

    if (!locale)
    {
        default_locale = defaultlocale();
        if (!default_locale.empty())
        {
            locale = default_locale.c_str();
        }
    }

    if (locale) 
    {
        std::string up_locale = StringHelper::toupper(locale);
        if (up_locale.find("UTF-8") != std::string::npos)
        {
            return utf8towchar(str);
        }
        else if (up_locale.find("UTF-7") != std::string::npos)
        {
            return utf7towchar(str);
        }
        else if (up_locale.find("UTF-16LE") != std::string::npos)
        {
            return utf16letowchar(str);
        }
        else if (up_locale.find("UTF-16BE") != std::string::npos)
        {
            return utf16betowchar(str);
        }
        else if (up_locale.find("UTF-32LE") != std::string::npos)
        {
            return utf32letowchar(str);
        }
        else if (up_locale.find("UTF-32BE") != std::string::npos)
        {
            return utf32betowchar(str);
        }
    }

    std::unique_lock<std::mutex> lck(char_wchar_lock);
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

std::wstring StringHelper::towchar(const std::string &str)
{
#if defined(_MSC_VER)
    return transbytestowchar(str, CP_ACP);
#elif defined(__GNUC__)
    return towchar(str, NULL);
#else
#error unsupported compiler
#endif
}

std::string StringHelper::tochar(const std::wstring &wstr, const char *locale)
{
    std::string result;
    if (wstr.empty()) return result;
    size_t wstr_len = wstr.length();
    char *buf = NULL;
    std::string cur_locale;
    std::string default_locale;

    if (!locale)
    {
        default_locale = defaultlocale();
        if (!default_locale.empty())
        {
            locale = default_locale.c_str();
        }
    }

    if (locale)
    {
        std::string up_locale = StringHelper::toupper(locale);
        if (up_locale.find("UTF-8") != std::string::npos)
        {
            return wchartoutf8(wstr);
        }
        else if (up_locale.find("UTF-7") != std::string::npos)
        {
            return wchartoutf7(wstr);
        }
        else if (up_locale.find("UTF-16LE") != std::string::npos)
        {
            return wchartoutf16le(wstr);
        }
        else if (up_locale.find("UTF-16BE") != std::string::npos)
        {
            return wchartoutf16be(wstr);
        }
        else if (up_locale.find("UTF-32LE") != std::string::npos)
        {
            return wchartoutf32le(wstr);
        }
        else if (up_locale.find("UTF-32BE") != std::string::npos)
        {
            return wchartoutf32be(wstr);
        }
    }

    std::unique_lock<std::mutex> lck(char_wchar_lock);
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

std::string StringHelper::tochar(const std::wstring &wstr)
{
#if defined(_MSC_VER)
    return wchartotransbytes(wstr, CP_ACP);
#elif defined(__GNUC__)
    return tochar(wstr, NULL);
#else
#error unsupported compiler
#endif
}

std::wstring StringHelper::utf8towchar(const std::string &str)
{
    if (str.empty()) return L"";
#if defined(_MSC_VER)
    return transbytestowchar(str, CP_UTF8);
#elif defined(__GNUC__)
    return transbytestowchar(str, "UTF-8");
#else
#error unsupported compiler
#endif
}

std::string StringHelper::wchartoutf8(const std::wstring &wstr)
{
    if (wstr.empty()) return "";
#if defined(_MSC_VER)
    return wchartotransbytes(wstr, CP_UTF8);
#elif defined(__GNUC__)
    return wchartotransbytes(wstr, "UTF-8");
#else
#error unsupported compiler
#endif
}

std::wstring StringHelper::utf7towchar(const std::string &str)
{
    if (str.empty()) return L"";
#if defined(_MSC_VER)
    return transbytestowchar(str, CP_UTF7);
#elif defined(__GNUC__)
    return transbytestowchar(str, "UTF-7");
#else
#error unsupported compiler
#endif
}

std::string StringHelper::wchartoutf7(const std::wstring &wstr)
{
    if (wstr.empty()) return "";
#if defined(_MSC_VER)
    return wchartotransbytes(wstr, CP_UTF7);
#elif defined(__GNUC__)
    return wchartotransbytes(wstr, "UTF-7");
#else
#error unsupported compiler
#endif
}

std::wstring StringHelper::utf16letowchar(const std::string &str)
{
    if (str.empty()) return L"";
#if defined(_MSC_VER)
    return transbytestowchar(str, CP_UTF16LE);
#elif defined(__GNUC__)
    return transbytestowchar(str, "UTF-16LE");
#else
#error unsupported compiler
#endif
}

std::string StringHelper::wchartoutf16le(const std::wstring &wstr)
{
    if (wstr.empty()) return "";
#if defined(_MSC_VER)
    return wchartotransbytes(wstr, CP_UTF16LE);
#elif defined(__GNUC__)
    return wchartotransbytes(wstr, "UTF-16LE");
#else
#error unsupported compiler
#endif
}

std::wstring StringHelper::utf16betowchar(const std::string &str)
{
    if (str.empty()) return L"";
#if defined(_MSC_VER)
    return transbytestowchar(str, CP_UTF16BE);
#elif defined(__GNUC__)
    return transbytestowchar(str, "UTF-16BE");
#else
#error unsupported compiler
#endif
}

std::string StringHelper::wchartoutf16be(const std::wstring &wstr)
{
    if (wstr.empty()) return "";
#if defined(_MSC_VER)
    return wchartotransbytes(wstr, CP_UTF16BE);
#elif defined(__GNUC__)
    return wchartotransbytes(wstr, "UTF-16BE");
#else
#error unsupported compiler
#endif
}

std::wstring StringHelper::utf32letowchar(const std::string &str)
{
    if (str.empty()) return L"";
#if defined(_MSC_VER)
    return transbytestowchar(str, CP_UTF32LE);
#elif defined(__GNUC__)
    return transbytestowchar(str, "UTF-32LE");
#else
#error unsupported compiler
#endif
}

std::string StringHelper::wchartoutf32le(const std::wstring &wstr)
{
    if (wstr.empty()) return "";
#if defined(_MSC_VER)
    return wchartotransbytes(wstr, CP_UTF32LE);
#elif defined(__GNUC__)
    return wchartotransbytes(wstr, "UTF-32LE");
#else
#error unsupported compiler
#endif
}

std::wstring StringHelper::utf32betowchar(const std::string &str)
{
    if (str.empty()) return L"";
#if defined(_MSC_VER)
    return transbytestowchar(str, CP_UTF32BE);
#elif defined(__GNUC__)
    return transbytestowchar(str, "UTF-32BE");
#else
#error unsupported compiler
#endif
}

std::string StringHelper::wchartoutf32be(const std::wstring &wstr)
{
    if (wstr.empty()) return "";
#if defined(_MSC_VER)
    return wchartotransbytes(wstr, CP_UTF32BE);
#elif defined(__GNUC__)
    return wchartotransbytes(wstr, "UTF-32BE");
#else
#error unsupported compiler
#endif
}

#if defined(_MSC_VER)
std::wstring StringHelper::transbytestowchar(const std::string &str, unsigned int code_page)
{
    if (str.empty()) return L"";
    wchar_t *buf = NULL;
    u_int nLen = MultiByteToWideChar(code_page, 0, str.c_str(), str.size(), NULL, 0);
    if (nLen <= 0)
    {
        return L"";
    }
    buf = new (std::nothrow) wchar_t[nLen];
    if (buf == NULL)
    {
        return L"";
    }
    u_int nRtn = MultiByteToWideChar(code_page, 0, str.c_str(), str.size(), buf, nLen);
    if (nRtn != nLen)
    {
        delete[]buf;
        return L"";
    }
    std::wstring result(buf, nRtn);
    delete[]buf;
    return result;
}

std::string StringHelper::wchartotransbytes(const std::wstring &wstr, unsigned int code_page)
{
    if (wstr.empty()) return "";
    char *buf = NULL;
    u_int nLen = WideCharToMultiByte(code_page, 0, wstr.c_str(), wstr.size(), NULL, 0, NULL, NULL);
    if (nLen <= 0)
    {
        return "";
    }
    buf = new (std::nothrow) char[nLen];
    if (buf == NULL)
    {
        return "";
    }
    u_int nRtn = WideCharToMultiByte(code_page, 0, wstr.c_str(), wstr.size(), buf, nLen, NULL, NULL);
    if (nRtn != nLen)
    {
        delete[]buf;
        return "";
    }
    std::string result(buf, nRtn);
    delete[]buf;
    return result;
}
#elif defined(__GNUC__)
std::wstring StringHelper::transbytestowchar(const std::string &str, const std::string &character)
{
    if (str.empty()) return L"";
    if (character.empty()) return L"";
    iconv_t cd;
    cd = iconv_open("WCHAR_T", character.c_str());
    if ((iconv_t)-1 == cd)
    {
        return L"";
    }
    char* inbuffer = (char *)str.c_str();
    size_t srcLen = str.size();
    size_t outLen = (srcLen + 1) * sizeof(wchar_t);
    char* outbuff = new (std::nothrow) char[outLen];
    if (outbuff == NULL)
    {
        iconv_close(cd);
        return L"";
    }
    char *begin = outbuff;
    auto retsize = iconv(cd, (char **)&inbuffer, (size_t *)&srcLen, &outbuff, (size_t *)&outLen);
    retsize = iconv(cd, NULL, NULL, &outbuff, (size_t *)&outLen); //deal the reset bytes
    iconv_close(cd);
    if ((size_t)-1 == retsize)
    {
        delete[]begin;
        return L"";
    }
    std::wstring result((wchar_t*)begin, (outbuff - begin) / sizeof(wchar_t));
    delete[]begin;
    return result;
}

std::string StringHelper::wchartotransbytes(const std::wstring &wstr, const std::string &character)
{
    if (wstr.empty()) return "";
    if (character.empty()) return "";
    iconv_t cd;
    cd = iconv_open(character.c_str(), "WCHAR_T");
    if ((iconv_t)-1 == cd)
    {
        return "";
    }
    char* inbuffer = (char *)wstr.c_str();
    size_t srcLen = wstr.size() * sizeof(wchar_t);
    size_t outLen = srcLen + 1;
    char* outbuff = new (std::nothrow) char[outLen];
    if (outbuff == NULL)
    {
        iconv_close(cd);
        return "";
    }
    char *begin = outbuff;
    auto retsize = iconv(cd, (char **)&inbuffer, (size_t *)&srcLen, &outbuff, (size_t *)&outLen);
    retsize = iconv(cd, NULL, NULL, &outbuff, (size_t *)&outLen);//deal the reset bytes
    iconv_close(cd);
    if ((size_t)-1 == retsize)
    {
        delete[]begin;
        return "";
    }
    std::string result(begin, outbuff - begin);
    delete[]begin;
    return result;
}

std::string StringHelper::transbytestotransbytes(const std::string &str, const std::string &f_character, const std::string &t_character)
{
    if (str.empty()) return "";
    if (f_character.empty()) return "";
    if (t_character.empty()) return "";
    iconv_t cd;
    cd = iconv_open(t_character.c_str(), f_character.c_str());
    if ((iconv_t)-1 == cd)
    {
        return "";
    }
    char* inbuffer = (char *)str.c_str();
    size_t srcLen = str.size();
    size_t outLen = (srcLen + 1) * 4;
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
    std::string result(begin, outbuff - begin);
    delete[]begin;
    return result;
}
#else
#error unsupported compiler
#endif

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