// Curl.cpp : Defines the entry point for the console application.
//

#include <iostream>
#include <set>
#include <map>
#include <vector>
#include <sstream>
#include <algorithm>
#include <fstream>
#if defined(_MSC_VER)
#include <curl\CurlHelper.h>
#elif defined(__GNUC__)
#include <curl/CurlHelper.h>
#else
#error unsupported compiler
#endif
using namespace std;

int main()
{
    CurlHelper baidu(std::string("http://www.baidu.com"));

    {
        std::vector<std::string> vc;
        vc.emplace_back("User-Agent:Mozilla/4.04[en](Win95;I;Nav)");
        std::string res_body;
        CurlHelper::HttpHeader res_header;
        u_int res_code;
        baidu.CurlGetString(vc, &res_code, &res_body, &res_header);
        for (auto head : res_header)
        {
            std::cout << head.first << " : " << head.second << std::endl;
        }
        std::cout << std::endl;
        std::cout << res_body << std::endl;
    }

    {
        std::vector<std::string> vc;
        vc.emplace_back("User-Agent:Mozilla/4.04[en](Win95;I;Nav)");
        CurlHelper::HttpHeader res_header;
        u_int res_code;
        std::string file_name = "baidu.html";
        baidu.CurlGetFile(vc, &res_code, &file_name, &res_header);
        for (auto head : res_header)
        {
            std::cout << head.first << " : " << head.second << std::endl;
        }
        std::string res_body;
        std::fstream fs("baidu.html");
        fs.seekg(0,ios::end);
        auto size = fs.tellg();
        fs.seekg(0, ios::beg);
        char *data = new char[(int)size+1];
        fs.read(data, size);
        std::cout << std::endl;
        std::cout << data;
    }

    {
        std::vector<std::string> vc;
        vc.emplace_back("User-Agent:Mozilla/4.04[en](Win95;I;Nav)");
        std::string post_data = "test";
        std::string res_body;
        CurlHelper::HttpHeader res_header;
        u_int res_code;
        baidu.CurlPostString(vc, post_data, &res_code, &res_body, &res_header);
        for (auto head : res_header)
        {
            std::cout << head.first << " : " << head.second << std::endl;
        }
        std::cout << std::endl;
        std::cout << res_body << std::endl;
    }


    {
        std::vector<std::string> vc;
        vc.emplace_back("User-Agent:Mozilla/4.04[en](Win95;I;Nav)");
        std::vector<std::pair<std::string, std::string>> post_data;
        post_data.emplace_back(std::pair<std::string, std::string>("abc1", "test1"));
        post_data.emplace_back(std::pair<std::string, std::string>("abc2", "test2"));
        post_data.emplace_back(std::pair<std::string, std::string>("abc1", "test3"));
        std::set<std::string> file_paths;
        //file_paths.insert("test1.txt");
        //file_paths.insert("test2.txt");
        std::string res_body;
        CurlHelper::HttpHeader res_header;
        u_int res_code;
        baidu.CurlPostString(vc, post_data, file_paths, &res_code, &res_body, &res_header);
        for (auto head : res_header)
        {
            std::cout << head.first << " : " << head.second << std::endl;
        }
        std::cout << std::endl;
        std::cout << res_body << std::endl;
    }
    return 0;
}
