#ifndef CURL_HELPER_H_INCLUDED
#define CURL_HELPER_H_INCLUDED

#include <string>
#include <vector>
#include <map>
#include <set>
#include <fstream>
#if defined(_MSC_VER)
#include <curl\libcurl\include\curl\curl.h>
#elif defined(__GNUC__)
#include <curl/libcurl/include/curl/curl.h>
#else
#error unsupported compiler
#endif

class CurlHelper
{
private:
    class Util
    {
    public:
        //remove the blank at both end of the string
        static std::string& trim(std::string &s)
        {
            return ltrim(rtrim(s));
        }

        //remove the blank at right end of the string
        static std::string& rtrim(std::string &s)
        {
            if (s.empty())  return s;

            return s.erase(s.find_last_not_of(" ") + 1);
        }

        //remove the blank at left end of the string
        static std::string& ltrim(std::string &s)
        {
            if (s.empty())  return s;

            return s.erase(0, s.find_first_not_of(" "));
        }
    };

public:
    typedef std::map<std::string, std::string> HttpHeader;

private:
    const static u_int CURL_DEFAULT_TIME_OUT = 600;

public:
    /**
    *note ssl_cainfo must be the path of PEM format CA cert
    */
    CurlHelper(const std::string &url, bool is_need_ssl_auth = true, const std::string &ssl_cainfo = "", bool is_need_proxy = false, const std::string &proxy = "", u_int time_out = CurlHelper::CURL_DEFAULT_TIME_OUT)
        :m_url(url), m_is_need_ssl_auth(is_need_ssl_auth), m_ssl_cainfo(ssl_cainfo), m_is_need_proxy(is_need_proxy), m_proxy(proxy), m_time_out(time_out), m_err_info{0}
    {
    }

    /**
    *use get method to get string info from server
    *vec_headers[in] the headers that you want to add
    *res_code[out] the responce code from the server
    *res_body[out] the responce body from the server
    *res_header[out] the responce headers from the server
    *return zero for success, otherwise failed
    */
    virtual u_int CurlGetString(std::vector<std::string> &vec_headers, u_int *res_code = NULL, std::string *res_body = NULL, HttpHeader *res_header = NULL);
    /**
    *use get method to get file from server
    *vec_headers[in] the headers that you want to add
    *res_code[out] the responce code from the server
    *file_name[in] the file path that you want to store the responce body from the server
    *res_header[out] the responce headers from the server
    *return zero for success, otherwise failed
    */
    virtual u_int CurlGetFile(std::vector<std::string> &vec_headers, u_int *res_code = NULL, std::string *file_name = NULL, HttpHeader *res_header = NULL);
    /**
    *use post method to post string to server
    *vec_headers[in] the headers that you want to add
    *post_body[in] the string that you want to post
    *res_code[out] the responce code from the server
    *res_body[out] the responce body from the server
    *res_header[out] the responce headers from the server
    *return zero for success, otherwise failed
    */
    virtual u_int CurlPostString(std::vector<std::string> &vec_headers, std::string &post_body, u_int *res_code = NULL, std::string *res_body = NULL, HttpHeader *res_header = NULL);
    /**
    *use post method to post multi sections to server
    *vec_headers[in] the headers that you want to add
    *post_datas[in] the strings that you want to post
    *file_paths[in] the file content that you want to post
    *res_code[out] the responce code from the server
    *res_body[out] the responce body from the server
    *res_header[out] the responce headers from the server
    *return zero for success, otherwise failed
    */
    virtual u_int CurlPostString(std::vector<std::string> &vec_headers, std::vector<std::pair<std::string,std::string>> &post_datas, std::set<std::string> &file_paths, u_int *res_code = NULL, std::string *res_body = NULL, HttpHeader *res_header = NULL);
    virtual char *GetLastCurlErrorInfo()
    {
        return m_err_info;
    }

    virtual ~CurlHelper(){}

private:
    //the function will be used to copy the rsp stream to the string you put
    static size_t CurlStringBodyWriteCallback(void* buffer, size_t size, size_t nmemb, void* stream);
    //the function will be used to copy the rsp stream to the string you put
    static size_t CurlMapHeaderWriteCallback(void* buffer, size_t size, size_t nmemb, void* stream);
    //set the curl options
    void CurlOptionSet(CURL* curl, curl_slist *headers, HttpHeader *res_header = NULL, std::string *res_body = NULL, FILE *save_file = NULL, bool is_post = false, const std::string &post_body = "", struct curl_httppost* post = NULL);

private:
    std::string m_url;//the url for surffing
    bool m_is_need_proxy;//is need proxy to the dst
    std::string m_proxy;//the proxy ip:port
    u_int m_time_out;//surffing time out
    bool m_is_need_ssl_auth;//is need ssl ca auth
    std::string m_ssl_cainfo;//https cert info, give the path
    char m_err_info[CURL_ERROR_SIZE];
};

#endif