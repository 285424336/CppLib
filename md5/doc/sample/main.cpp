// MD5.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <string>
#include <iostream>
#include <iomanip>
#include <sstream>
#include "md5.h"

std::string GenerateHexString(const byte *bytes, uint32_t num, bool is_uppercase = true)
{
    if (bytes == NULL || num == 0) return "";

    std::stringstream ss;
    ss << std::hex;
    if (is_uppercase)
    {
        ss << std::uppercase;
    }
    for (int i = 0; i < num; i++)
    {
        ss << std::setfill('0') << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return ss.str();
}

int main()
{
    std::string a = "123456789";
    std::cout << GenerateHexString(MD5(a).getDigest(), 16) << std::endl;
    std::cout << GenerateHexString(MD5("a.txt").getDigest(), 16) << std::endl;
    return 0;
}



