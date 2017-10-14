#include "CurlHelper.h"
#include <sstream>

u_int CurlHelper::CurlGetString(const std::vector<std::string> &vec_headers, u_int *res_code, std::string *res_body, HttpHeader *res_header, std::vector<std::map<std::string, std::string>> *peer_cert_infos)
{
    CURL* curl = curl_easy_init();
    struct curl_slist *headers = NULL;
    u_int ret = CURLE_OK;
    long code = 0;//must be long type

    if (curl == NULL) return CURLE_FAILED_INIT;

    auto end = vec_headers.end();
    for (auto it = vec_headers.begin(); it != end; ++it)
    {
        headers = curl_slist_append(headers, it->c_str());
    }

    CurlOptionSet(curl, headers, res_header, res_body, NULL, false, "", NULL, peer_cert_infos!=NULL);

    ret = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);

    if (res_code)
    {
        *res_code = code;
    }

    if (headers)
    {
        curl_slist_free_all(headers);
    }

    std::string location_url;
    if (ret == CURLE_OK && code >= 300 && code < 400 && m_is_follow_redir && m_max_redir)
    {
        char *url = NULL;
        curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &url);
        if (url)
        {
            location_url = url;
        }
    }

    if (!ret && peer_cert_infos) {
        struct curl_certinfo *ci;
        ret = curl_easy_getinfo(curl, CURLINFO_CERTINFO, &ci);
        if (!ret) {
            for (int i = 0; i < ci->num_of_certs; i++) {
                struct curl_slist *slist;
                std::map<std::string, std::string> cert_info;
                for (slist = ci->certinfo[i]; slist; slist = slist->next) {
                    std::string info = slist->data;
                    size_t pos = info.find_first_of(":");
                    if (pos != std::string::npos) {
                        cert_info[std::string(info, 0, pos)] = std::string(info, pos + 1);
                    }
                }
                peer_cert_infos->emplace_back(cert_info);
            }
        }
    }
    curl_easy_cleanup(curl);

    if (!location_url.empty()) 
    {
        if (res_body) res_body->clear();
        if (res_header) res_header->clear();
        if (peer_cert_infos) peer_cert_infos->clear();
        CurlHelper inner(location_url, false, "", m_is_need_proxy, m_proxy, m_time_out, true, m_max_redir - 1);
        return inner.CurlGetString(vec_headers, res_code, res_body, res_header, peer_cert_infos);
    }
    return ret;
}

u_int CurlHelper::CurlGetFile(const std::vector<std::string> &vec_headers, u_int *res_code, std::string *file_name, HttpHeader *res_header, std::vector<std::map<std::string, std::string>> *peer_cert_infos)
{
    CURL* curl = curl_easy_init();
    struct curl_slist *headers = NULL;
    u_int ret = CURLE_OK;
    FILE *file = NULL;
    long code = 0;//must be long type

    if (curl == NULL) return CURLE_FAILED_INIT;

    auto end = vec_headers.end();
    for (auto it = vec_headers.begin(); it != end; ++it)
    {
        headers = curl_slist_append(headers, it->c_str());
    }

    if (file_name && !file_name->empty())
    {
#if defined(_MSC_VER)
        errno_t res = fopen_s(&file, file_name->c_str(), "wb");
        if (res == EINVAL || file == NULL) return CURLE_FILE_COULDNT_READ_FILE;
#elif defined(__GNUC__)
        file = fopen(file_name->c_str(), "wb");
        if (file == NULL) return CURLE_FILE_COULDNT_READ_FILE;
#else
#error unsupported compiler
#endif
    }

    CurlOptionSet(curl, headers, res_header, NULL, file, false, "", NULL, peer_cert_infos != NULL);

    ret = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);

    if (res_code)
    {
        *res_code = code;
    }

    if (headers)
    {
        curl_slist_free_all(headers);
    }

    if (file)
    {
        fclose(file);
    }

    std::string location_url;
    if (ret == CURLE_OK && code >= 300 && code < 400 && m_is_follow_redir && m_max_redir)
    {
        char *url = NULL;
        curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &url);
        if (url)
        {
            location_url = url;
        }
    }

    if (!ret && peer_cert_infos) {
        struct curl_certinfo *ci;
        ret = curl_easy_getinfo(curl, CURLINFO_CERTINFO, &ci);
        if (!ret) {
            for (int i = 0; i < ci->num_of_certs; i++) {
                struct curl_slist *slist;
                std::map<std::string, std::string> cert_info;
                for (slist = ci->certinfo[i]; slist; slist = slist->next) {
                    std::string info = slist->data;
                    size_t pos = info.find_first_of(":");
                    if (pos != std::string::npos) {
                        cert_info[std::string(info, 0, pos)] = std::string(info, pos + 1);
                    }
                }
                peer_cert_infos->emplace_back(cert_info);
            }
        }
    }
    curl_easy_cleanup(curl);

    if (!location_url.empty()) 
    {
        if (res_header) res_header->clear();
        if (peer_cert_infos) peer_cert_infos->clear();
        CurlHelper inner(location_url, false, "", m_is_need_proxy, m_proxy, m_time_out, true, m_max_redir - 1);
        return inner.CurlGetFile(vec_headers, res_code, file_name, res_header, peer_cert_infos);
    }
    return ret;
}

u_int CurlHelper::CurlPostString(const std::vector<std::string> &vec_headers, const std::string &post_body, u_int *res_code, std::string *res_body, HttpHeader *res_header, std::vector<std::map<std::string, std::string>> *peer_cert_infos)
{
    CURL* curl = curl_easy_init();
    struct curl_slist *headers = NULL;
    u_int ret = CURLE_OK;
    long code = 0;//must be long type

    if (curl == NULL) return CURLE_FAILED_INIT;

    auto end = vec_headers.end();
    for (auto it = vec_headers.begin(); it != end; ++it)
    {
        headers = curl_slist_append(headers, it->c_str());
    }

    CurlOptionSet(curl, headers, res_header, res_body, NULL, true, post_body, NULL, peer_cert_infos != NULL);

    ret = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);

    if (res_code)
    {
        *res_code = code;
    }

    if (headers)
    {
        curl_slist_free_all(headers);
    }

    std::string location_url;
    if (ret == CURLE_OK && code >= 300 && code < 400 && m_is_follow_redir && m_max_redir)
    {
        char *url = NULL;
        curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &url);
        if (url)
        {
            location_url = url;
        }
    }

    if (!ret && peer_cert_infos) {
        struct curl_certinfo *ci;
        ret = curl_easy_getinfo(curl, CURLINFO_CERTINFO, &ci);
        if (!ret) {
            for (int i = 0; i < ci->num_of_certs; i++) {
                struct curl_slist *slist;
                std::map<std::string, std::string> cert_info;
                for (slist = ci->certinfo[i]; slist; slist = slist->next) {
                    std::string info = slist->data;
                    size_t pos = info.find_first_of(":");
                    if (pos != std::string::npos) {
                        cert_info[std::string(info, 0, pos)] = std::string(info, pos + 1);
                    }
                }
                peer_cert_infos->emplace_back(cert_info);
            }
        }
    }
    curl_easy_cleanup(curl);

    if (!location_url.empty())
    {
        if (res_body) res_body->clear();
        if (res_header) res_header->clear();
        if (peer_cert_infos) peer_cert_infos->clear();
        CurlHelper inner(location_url, false, "", m_is_need_proxy, m_proxy, m_time_out, true, m_max_redir - 1);
        return inner.CurlPostString(vec_headers, post_body, res_code, res_body, res_header, peer_cert_infos);
    }
    return ret;
}

u_int CurlHelper::CurlPostString(const std::vector<std::string> &vec_headers, const std::vector<std::pair<std::string, std::string> > &post_datas, const std::set<std::string> &file_paths, u_int *res_code, std::string *res_body, HttpHeader *res_header, std::vector<std::map<std::string, std::string>> *peer_cert_infos)
{
    CURL* curl = curl_easy_init();
    struct curl_slist *headers = NULL;
    u_int ret = CURLE_OK;
    struct curl_httppost* post = NULL;
    struct curl_httppost* last = NULL;
    long code = 0; //must be long type

    if (curl == NULL) return CURLE_FAILED_INIT;

    auto end = vec_headers.end();
    for (auto it = vec_headers.begin(); it != end; ++it)
    {
        headers = curl_slist_append(headers, it->c_str());
    }

    for (auto vit = post_datas.begin(); vit != post_datas.end(); vit++)
    {
        curl_formadd(&post, &last, CURLFORM_COPYNAME, (*vit).first.c_str(),
            CURLFORM_COPYCONTENTS, (*vit).second.c_str(), CURLFORM_END);
    }

    std::set<std::string>::iterator sit;
    for (sit = file_paths.begin(); sit != file_paths.end(); sit++)
    {
        curl_formadd(&post, &last, CURLFORM_COPYNAME, "file", CURLFORM_FILE, (*sit).c_str(), CURLFORM_END);
    }

    CurlOptionSet(curl, headers, res_header, res_body, NULL, true, std::string(""), post, peer_cert_infos != NULL);

    ret = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    if (res_code)
    {
        *res_code = code;
    }

    if (headers)
    {
        curl_slist_free_all(headers);
    }

    if (post)
    {
        curl_formfree(post);
    }

    std::string location_url;
    if (ret == CURLE_OK && code >= 300 && code < 400 && m_is_follow_redir && m_max_redir)
    {
        char *url = NULL;
        curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &url);
        if (url)
        {
            location_url = url;
        }
    }

    if (!ret && peer_cert_infos) {
        struct curl_certinfo *ci;
        ret = curl_easy_getinfo(curl, CURLINFO_CERTINFO, &ci);
        if (!ret) {
            for (int i = 0; i < ci->num_of_certs; i++) {
                struct curl_slist *slist;
                std::map<std::string, std::string> cert_info;
                for (slist = ci->certinfo[i]; slist; slist = slist->next) {
                    std::string info = slist->data;
                    size_t pos = info.find_first_of(":");
                    if (pos != std::string::npos) {
                        cert_info[std::string(info, 0, pos)] = std::string(info, pos + 1);
                    }
                }
                peer_cert_infos->emplace_back(cert_info);
            }
        }
    }
    curl_easy_cleanup(curl);

    if (!location_url.empty()) 
    {
        if (res_body) res_body->clear();
        if (res_header) res_header->clear();
        if (peer_cert_infos) peer_cert_infos->clear();
        CurlHelper inner(location_url, false, "", m_is_need_proxy, m_proxy, m_time_out, true, m_max_redir - 1);
        return inner.CurlPostString(vec_headers, post_datas, file_paths, res_code, res_body, res_header, peer_cert_infos);
    }
    return ret;
}

size_t CurlHelper::CurlStringBodyWriteCallback(void* buffer, size_t size, size_t nmemb, void* stream)
{
    std::string* str_stream = reinterpret_cast<std::string*>(stream);
    size_t bytes = size*nmemb;

    if (buffer && str_stream && bytes)
    {
        *str_stream += std::string((const char*)buffer, bytes);
    }

    return bytes;
}

size_t CurlHelper::CurlMapHeaderWriteCallback(void* buffer, size_t size, size_t nmemb, void* stream)
{
    HttpHeader* map_stream = reinterpret_cast<HttpHeader*>(stream);
    size_t bytes = size*nmemb;
    std::string str_buf((const char*)buffer, bytes);
    std::string::size_type field_off = str_buf.find(':');
    std::string::size_type value_off = str_buf.rfind("\r\n");
    if (value_off == str_buf.npos)
    {
        value_off = str_buf.rfind("\n");
    }

    if (field_off != str_buf.npos && value_off != str_buf.npos && value_off > field_off && map_stream)
    {
        std::string key((const char*)buffer, field_off);
        std::string value((const char*)buffer + field_off + 1, value_off - field_off - 1);
        Util::trim(key);
        Util::trim(value);

        if (map_stream->find(key) != map_stream->end())
        {
            uint32_t i = 1;
            while (true)
            {
                std::stringstream ss;
                ss << key << "_" << i;
                if (map_stream->find(ss.str()) == map_stream->end())
                {
                    key = ss.str();
                    break;
                }
                i++;
            }
        }
        (*map_stream)[key] = value;
    }

    return bytes;
}

void CurlHelper::CurlOptionSet(CURL* curl, curl_slist *headers, HttpHeader *res_header, std::string *res_body, FILE *save_file, bool is_post, const std::string &post_body, struct curl_httppost* post, bool is_need_cert_info)
{
    curl_easy_setopt(curl, CURLOPT_URL, m_url.c_str());
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, m_time_out);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, m_err_info);

    if (m_is_need_ssl_auth)
    {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);//VERIFY the digital signatures with the ca set in opt CURLOPT_CAINFO
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);//VERIFY the host name with the ca set in opt CURLOPT_CAINFO
        if (!m_ssl_cainfo.empty()) curl_easy_setopt(curl, CURLOPT_CAINFO, m_ssl_cainfo.c_str());//set the ca path
    }
    else
    {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);//VERIFY the digital signatures with the ca set in opt CURLOPT_CAINFO
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);//VERIFY the host name with the ca set in opt CURLOPT_CAINFO
    }

    if (headers)
    {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }

    if (m_is_need_proxy)
    {
        curl_easy_setopt(curl, CURLOPT_PROXY, m_proxy.c_str());
    }

    if (res_header)
    {
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, CurlHelper::CurlMapHeaderWriteCallback);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, res_header);
    }

    if (res_body)
    {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlHelper::CurlStringBodyWriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, res_body);
    }
    else if (save_file)
    {
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, save_file);
    }
    else
    {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlHelper::CurlStringBodyWriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, NULL);
    }

    if (is_post == true)
    {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        if (post == NULL)
        {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_body.data());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, post_body.size());
        }
        else
        {
            curl_easy_setopt(curl, CURLOPT_HTTPPOST, post);
        }
    }
    else
    {
        curl_easy_setopt(curl, CURLOPT_POST, 0L);
    }

    if (is_need_cert_info)
    {
        curl_easy_setopt(curl, CURLOPT_CERTINFO, 1L);
    }
    else
    {
        curl_easy_setopt(curl, CURLOPT_CERTINFO, 0L);
    }

    if (m_accept_encode)
    {
        curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
    }
}