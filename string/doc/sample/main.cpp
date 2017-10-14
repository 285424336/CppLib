// StringHelper.cpp : Defines the entry point for the console application.
//

#if defined(_MSC_VER)
#include <windows.h>
#include <string\StringHelper.h>
#include <file\FileHelper.h>
#include <string\Lang.h>
#elif defined(__GNUC__)
#include <string/StringHelper.h>
#include <file/FileHelper.h>
#else
#error unsupported compiler
#endif

#include <iostream>
#include <sstream>
#include <iomanip>
#include <thread>
#include <vector>

template <typename TARGET>
void ConvertTestHelpStr2Int()
{
    std::vector<std::string> vc;
    vc.emplace_back("");
    vc.emplace_back("+0");
    vc.emplace_back("1");
    vc.emplace_back("-0");
    vc.emplace_back("-127");
    vc.emplace_back("-128");
    vc.emplace_back("-255");
    vc.emplace_back("-256");
    vc.emplace_back("-32767");
    vc.emplace_back("127");
    vc.emplace_back("128");
    vc.emplace_back("255");
    vc.emplace_back("256");
    vc.emplace_back("65535");
    vc.emplace_back("a128");
    vc.emplace_back("128a");
    for (auto src : vc)
    {
        try
        {
            std::cout << "    src: " << src << " dst: " << (long long)StringHelper::convert<TARGET>(src) << std::endl;
        }
        catch (std::bad_cast &e)
        {
            std::cout << "    src: " << src << " " << e.what() << std::endl;
        }
    }
}

void ConvertTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    {
        std::cout << "string to bool" << std::endl;
        ConvertTestHelpStr2Int<bool>();
    }

    {
        std::cout << "string to char" << std::endl;
        ConvertTestHelpStr2Int<char>();
    }
    {
        std::cout << "string to uchar" << std::endl;
        ConvertTestHelpStr2Int<unsigned char>();
    }
    {
        std::cout << "string to short" << std::endl;
        ConvertTestHelpStr2Int<short>();
    }
    {
        std::cout << "string to unsigned short" << std::endl;
        ConvertTestHelpStr2Int<unsigned short>();
    }
    {
        std::cout << "int to string" << std::endl;
        std::cout << "    src: " << "-1235" << " dst: " << StringHelper::convert<std::string, int>(-1235) << std::endl;
    }
    {
        std::cout << "int to short" << std::endl;
        std::cout << "    src: " << 0X0FFFF << " dst: " << StringHelper::convert<u_short, int>(0X0FFFF) << std::endl;
    }
    {
        std::cout << "char to string" << std::endl;
        std::cout << "    src: " << "-124" << " dst: " << StringHelper::convert<std::string, const char*>("-124") << std::endl;
    }
}

void SignedTypeCheckTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    typedef unsigned long long abcd;
    typedef long long dcef;
    std::cout << "u_char is signed " << StringHelper::is_signed<u_char>::value << std::endl;
    std::cout << "char is signed " << StringHelper::is_signed<char>::value << std::endl;
    std::cout << "u_short is signed " << StringHelper::is_signed<u_short>::value << std::endl;
    std::cout << "short is signed " << StringHelper::is_signed<short>::value << std::endl;
    std::cout << "u_int is signed " << StringHelper::is_signed<u_int>::value << std::endl;
    std::cout << "int is signed " << StringHelper::is_signed<int>::value << std::endl;
    std::cout << "u_long is signed " << StringHelper::is_signed<u_long>::value << std::endl;
    std::cout << "long is signed " << StringHelper::is_signed<long>::value << std::endl;
    std::cout << "unsigned long long is signed " << StringHelper::is_signed<unsigned long long>::value << std::endl;
    std::cout << "long long is signed " << StringHelper::is_signed<long long>::value << std::endl;
    std::cout << "typedef unsigned long long abcd is signed " << StringHelper::is_signed<abcd>::value << std::endl;
    std::cout << "typedef long long dcef is signed " << StringHelper::is_signed<dcef>::value << std::endl;
    std::cout << "std::vector<int> is signed " << StringHelper::is_signed<std::vector<int>>::value << std::endl;
}

void TrimTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    std::string src = "  abcd  ";
    std::cout << "    " << src << " " << StringHelper::trim(src) << std::endl;
    std::cout << "    " << src << " " << StringHelper::ltrim(src) << std::endl;
    std::cout << "    " << src << " " << StringHelper::rtrim(src) << std::endl;
}

void SplitTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    std::string src = ",,a,d,c,,d,";
    std::vector<std::string> vc = StringHelper::split(src, ",");
    std::cout << "    " << src << " spilt after: " << std::endl;
    for (auto sub : vc)
    {
        std::cout << "    " << sub << std::endl;
    }
}

void JoinTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    std::string src = ",,a,d,c,,d,";
    std::vector<std::string> vc = StringHelper::split(src, ",");
    std::cout << "    " << src << " spilt after: " << std::endl;
    for (auto sub : vc)
    {
        std::cout << "    " << sub << std::endl;
    }
    std::cout << "    " << StringHelper::join(vc, ":") << std::endl;
}

void ReplaceTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    std::string src = ",,a,d,c,,d,";
    std::cout<< "    " << src << " replace after: " << StringHelper::replace(src, ",", ":") << std::endl;
}

void ToUpperTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    std::string src = ",,a,d,c,,d,";
    std::cout << "    " << src << " to upper after: " << StringHelper::toupper(src) << std::endl;
}

void ToLowerTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    std::string src = ",,A,B,C,,D,";
    std::cout << "    " << src << " to upper after: " << StringHelper::tolower(src) << std::endl;
}

void ToCharTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    {
        std::wstring a = L"Âí³¿½ãleo";
#if defined(_MSC_VER)
        std::cout << StringHelper::tochar(a, "chs") << std::endl;
#elif defined(__GNUC__)
        std::cout << StringHelper::tochar(a, "zh_CN.UTF-8") << std::endl;
#else
#error unsupported compiler
#endif
    }
    {
        std::wstring a = L"leo";
        std::cout << StringHelper::tochar(a, NULL) << std::endl;
        std::cout << StringHelper::tochar(a, "C") << std::endl;
    }
}

void ToWCharTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    {
        std::string a = "Âí³¿½ãleo";
#if defined(_MSC_VER)
        std::cout << StringHelper::tochar(StringHelper::towchar(a, "chs"), "chs") << std::endl;
#elif defined(__GNUC__)
        std::cout << StringHelper::tochar(StringHelper::towchar(a, "zh_CN.UTF-8"), "zh_CN.UTF-8") << std::endl;
#else
#error unsupported compiler
#endif
    }
    {
        std::string a = "leo";
        std::wcout << StringHelper::towchar(a, NULL) << std::endl;
        std::cout << StringHelper::tochar(StringHelper::towchar(a, NULL), NULL) << std::endl;
        std::cout << StringHelper::tochar(StringHelper::towchar(a, "C"), "C") << std::endl;
    }
}

void wchartoutf8Test()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    {
        std::string name = "Âí³¿½ã";
#if defined(_MSC_VER)
        std::string utf8 = StringHelper::wchartoutf8(StringHelper::towchar(name, "chs"));
        FileHelper::SetFileContent("utf8.txt", utf8.c_str(), utf8.size());
        std::cout << "local: " << name << " utf-8: " << StringHelper::tochar(StringHelper::utf8towchar(utf8), "chs") << std::endl;
#elif defined(__GNUC__)
        std::string utf8 = StringHelper::wchartoutf8(StringHelper::towchar(name, "zh_CN.UTF-8"));
        FileHelper::SetFileContent("utf8.txt", utf8.c_str(), utf8.size());
        std::cout << "local: " << name << " utf-8: " << StringHelper::tochar(StringHelper::utf8towchar(utf8), "zh_CN.UTF-8") << std::endl;
#else
#error unsupported compiler
#endif
    }
}

void utf8towcharTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    {
#if defined(_MSC_VER)
        std::cout << StringHelper::tochar(StringHelper::utf8towchar(FileHelper::GetFileContent("utf8.txt")), "chs") << std::endl;
#elif defined(__GNUC__)
        std::cout << StringHelper::tochar(StringHelper::utf8towchar(FileHelper::GetFileContent("utf8.txt")), "zh_CN.UTF-8") << std::endl;
#else
#error unsupported compiler
#endif
    }
}

void wchartoutf7Test()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    {
        std::string name = "Âí³¿½ã";
#if defined(_MSC_VER)
        std::string utf8 = StringHelper::wchartoutf7(StringHelper::towchar(name, "zh-CN"));
        FileHelper::SetFileContent("utf7.txt", utf8.c_str(), utf8.size());
        std::cout << "local: " << name << " utf-7: " << StringHelper::tochar(StringHelper::utf7towchar(utf8), "zh-CN") << std::endl;
#elif defined(__GNUC__)
        std::string utf8 = StringHelper::wchartoutf7(StringHelper::towchar(name, "zh_CN.UTF-8"));
        FileHelper::SetFileContent("utf7.txt", utf8.c_str(), utf8.size());
        std::cout << "local: " << name << " utf-7: " << StringHelper::tochar(StringHelper::utf7towchar(utf8), "zh_CN.UTF-8") << std::endl;
#else
#error unsupported compiler
#endif
    }
}

void utf7towcharTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    {
#if defined(_MSC_VER)
        std::cout << StringHelper::tochar(StringHelper::utf7towchar(FileHelper::GetFileContent("utf7.txt")), "zh-CN") << std::endl;
#elif defined(__GNUC__)
        std::cout << StringHelper::tochar(StringHelper::utf7towchar(FileHelper::GetFileContent("utf7.txt")), "zh_CN.UTF-8") << std::endl;
#else
#error unsupported compiler
#endif
    }
}

void wchartoutf16leTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    {
        std::string name = "Âí³¿½ã";
#if defined(_MSC_VER)
        std::string utf8 = StringHelper::wchartoutf16le(StringHelper::towchar(name, "zh-CN"));
        FileHelper::SetFileContent("utf16le.txt", utf8.c_str(), utf8.size());
        std::cout << "local: " << name << " utf-16le: " << StringHelper::tochar(StringHelper::utf16letowchar(utf8), "zh-CN") << std::endl;
#elif defined(__GNUC__)
        std::string utf8 = StringHelper::wchartoutf16le(StringHelper::towchar(name, "zh_CN.UTF-8"));
        FileHelper::SetFileContent("utf16le.txt", utf8.c_str(), utf8.size());
        std::cout << "local: " << name << " utf-16le: " << StringHelper::tochar(StringHelper::utf16letowchar(utf8), "zh_CN.UTF-8") << std::endl;
#else
#error unsupported compiler
#endif
    }
}

void utf16letowcharTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    {
#if defined(_MSC_VER)
        std::cout << StringHelper::tochar(StringHelper::utf16letowchar(FileHelper::GetFileContent("utf16le.txt")), "zh-CN") << std::endl;
#elif defined(__GNUC__)
        std::cout << StringHelper::tochar(StringHelper::utf16letowchar(FileHelper::GetFileContent("utf16le.txt")), "zh_CN.UTF-8") << std::endl;
#else
#error unsupported compiler
#endif
    }
}

void wchartoutf16beTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    {
        std::string name = "Âí³¿½ã";
#if defined(_MSC_VER)
        std::string utf8 = StringHelper::wchartoutf16be(StringHelper::towchar(name, "zh-CN"));
        FileHelper::SetFileContent("utf16be.txt", utf8.c_str(), utf8.size());
        std::cout << "local: " << name << " utf-16be: " << StringHelper::tochar(StringHelper::utf16betowchar(utf8), "zh-CN") << std::endl;
#elif defined(__GNUC__)
        std::string utf8 = StringHelper::wchartoutf16be(StringHelper::towchar(name, "zh_CN.UTF-8"));
        FileHelper::SetFileContent("utf16be.txt", utf8.c_str(), utf8.size());
        std::cout << "local: " << name << " utf-16be: " << StringHelper::tochar(StringHelper::utf16betowchar(utf8), "zh_CN.UTF-8") << std::endl;
#else
#error unsupported compiler
#endif
    }
}

void utf16betowcharTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    {
#if defined(_MSC_VER)
        std::cout << StringHelper::tochar(StringHelper::utf16betowchar(FileHelper::GetFileContent("utf16be.txt")), "zh-CN") << std::endl;
#elif defined(__GNUC__)
        std::cout << StringHelper::tochar(StringHelper::utf16betowchar(FileHelper::GetFileContent("utf16be.txt")), "zh_CN.UTF-8") << std::endl;
#else
#error unsupported compiler
#endif
    }
}

void wchartoutf32leTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    {
        std::string name = "Âí³¿½ã";
#if defined(_MSC_VER)
        std::string utf8 = StringHelper::wchartoutf32le(StringHelper::towchar(name, "zh-CN"));
        FileHelper::SetFileContent("utf32le.txt", utf8.c_str(), utf8.size());
        std::cout << "local: " << name << " utf-32le: " << StringHelper::tochar(StringHelper::utf32letowchar(utf8), "zh-CN") << std::endl;
#elif defined(__GNUC__)
        std::string utf8 = StringHelper::wchartoutf32le(StringHelper::towchar(name, "zh_CN.UTF-8"));
        FileHelper::SetFileContent("utf32le.txt", utf8.c_str(), utf8.size());
        std::cout << "local: " << name << " utf-32le: " << StringHelper::tochar(StringHelper::utf32letowchar(utf8), "zh_CN.UTF-8") << std::endl;
#else
#error unsupported compiler
#endif
    }
}

void utf32letowcharTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    {
#if defined(_MSC_VER)
        std::cout << StringHelper::tochar(StringHelper::utf32letowchar(FileHelper::GetFileContent("utf32le.txt")), "zh-CN") << std::endl;
#elif defined(__GNUC__)
        std::cout << StringHelper::tochar(StringHelper::utf32letowchar(FileHelper::GetFileContent("utf32le.txt")), "zh_CN.UTF-8") << std::endl;
#else
#error unsupported compiler
#endif
    }
}

void wchartoutf32beTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    {
        std::string name = "Âí³¿½ã";
#if defined(_MSC_VER)
        std::string utf8 = StringHelper::wchartoutf32be(StringHelper::towchar(name, "zh-CN"));
        FileHelper::SetFileContent("utf32be.txt", utf8.c_str(), utf8.size());
        std::cout << "local: " << name << " utf-32be: " << StringHelper::tochar(StringHelper::utf32betowchar(utf8), "zh-CN") << std::endl;
#elif defined(__GNUC__)
        std::string utf8 = StringHelper::wchartoutf32be(StringHelper::towchar(name, "zh_CN.UTF-8"));
        FileHelper::SetFileContent("utf32be.txt", utf8.c_str(), utf8.size());
        std::cout << "local: " << name << " utf-32be: " << StringHelper::tochar(StringHelper::utf32betowchar(utf8), "zh_CN.UTF-8") << std::endl;
#else
#error unsupported compiler
#endif
    }
}

void utf32betowcharTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    {
#if defined(_MSC_VER)
        std::cout << StringHelper::tochar(StringHelper::utf32betowchar(FileHelper::GetFileContent("utf32be.txt")), "zh-CN") << std::endl;
#elif defined(__GNUC__)
        std::cout << StringHelper::tochar(StringHelper::utf32betowchar(FileHelper::GetFileContent("utf32be.txt")), "zh_CN.UTF-8") << std::endl;
#else
#error unsupported compiler
#endif
    }
}

void Hex2ByteTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    std::string hex = "1234567890ABCDEF";
    char buf[8] = { 0 };
    StringHelper::hex2byte(hex, buf, sizeof(buf));
    std::cout << "    " << hex << " to byte after: " << StringHelper::byte2basestr((u_char *)buf, sizeof(buf), "", StringHelper::hex, 2) << std::endl;
}

void Byte2BaseStrTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    char buf[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    std::cout << StringHelper::byte2basestr((u_char *)buf, sizeof(buf), "", StringHelper::dec, 1) << std::endl;
    std::cout << StringHelper::byte2basestr((u_char *)buf, sizeof(buf), "", StringHelper::hex, 2) << std::endl;
    std::cout << StringHelper::byte2basestr((u_char *)buf, sizeof(buf), "", StringHelper::oct, 3) << std::endl;
}

void GetStaticStringTest()
{
    static std::mutex out_lock;
    std::string s1 = "abc";
    const char *data1 = StringHelper::getstaticstring(s1);
    const char *data2 = StringHelper::getstaticstring(s1);

    std::string s2 = "def";
    const char *data3 = StringHelper::getstaticstring(s2);
    const char *data4 = StringHelper::getstaticstring(s2);
    const char *data5 = StringHelper::getstaticstring("%08lx", 16);
    {
        std::unique_lock<std::mutex> lock(out_lock);
        std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
        std::cout << "data1: " << (size_t)data1 << " data2: " << (size_t)data2 << std::endl;
        std::cout << "data1: " << data1 << " data2: " << data2 << std::endl;
        std::cout << "data3: " << (size_t)data3 << " data4: " << (size_t)data4 << std::endl;
        std::cout << "data3: " << data3 << " data4: " << data4 << std::endl;
        std::cout << "data5: " << data5 << std::endl;
    }
}

void DefaultLocaleTest()
{
    std::cout << __FUNCTION__ << "***********TEST************" << std::endl;
    std::cout << "default locale " << StringHelper::defaultlocale() << std::endl;
}

int main()
{
    SignedTypeCheckTest();
    ConvertTest();
    SplitTest();
    JoinTest();
    ReplaceTest();
    ToUpperTest();
    ToLowerTest();
    DefaultLocaleTest();
    ToCharTest();
    ToWCharTest();
    wchartoutf8Test();
    utf8towcharTest();
    wchartoutf7Test();
    utf7towcharTest();
    wchartoutf16leTest();
    utf16letowcharTest();
    wchartoutf16beTest();
    utf16betowcharTest();
    wchartoutf32leTest();
    utf32letowcharTest();
    wchartoutf32beTest();
    utf32betowcharTest();
    Hex2ByteTest();
    Byte2BaseStrTest();
    return 0;
}