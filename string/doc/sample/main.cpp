// StringHelper.cpp : Defines the entry point for the console application.
//

#if defined(_MSC_VER)
#include <windows.h>
#include <string\StringHelper.h>
#elif defined(__GNUC__)
#include <string/StringHelper.h>
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
        std::cout << StringHelper::tochar(StringHelper::towchar(a, NULL), NULL) << std::endl;
        std::cout << StringHelper::tochar(StringHelper::towchar(a, "C"), "C") << std::endl;
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

int main()
{
    SignedTypeCheckTest();
    ConvertTest();
    SplitTest();
    JoinTest();
    ReplaceTest();
    ToUpperTest();
    ToLowerTest();
    ToCharTest();
    ToWCharTest();
    Hex2ByteTest();
    Byte2BaseStrTest();
    return 0;
}