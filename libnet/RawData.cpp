#include "RawData.h"
#include <future>
#if defined(_MSC_VER)
#include <string\StringHelper.h>
#include <network\NetworkHelper.h>
#elif defined(__GNUC__)
#include <string/StringHelper.h>
#include <network/NetworkHelper.h>
#include <memory>
#else
#error unsupported compiler
#endif

template<class _Ty,
    class... _Types> inline
    typename std::enable_if<!std::is_array<_Ty>::value,
    std::unique_ptr<_Ty> >::type make_unique(_Types&&... _Args)
{	// make a unique_ptr
    return (std::unique_ptr<_Ty>(new _Ty(std::forward<_Types>(_Args)...)));
}

template<class _Ty> inline
typename std::enable_if<std::is_array<_Ty>::value && std::extent<_Ty>::value == 0,
    std::unique_ptr<_Ty> >::type make_unique(size_t _Size)
{	// make a unique_ptr
    typedef typename std::remove_extent<_Ty>::type _Elem;
    return (std::unique_ptr<_Ty>(new _Elem[_Size]()));
}

template<class _Ty,
    class... _Types>
    typename std::enable_if<std::extent<_Ty>::value != 0,
    void>::type make_unique(_Types&&...) = delete;

RawData::RawData() : NetBase()
{
    this->Reset();
}

RawData::~RawData()
{

}

void RawData::Reset()
{
    this->data = NULL;
    this->length = 0;
}

int RawData::ProtocolId() const
{
    return HEADER_TYPE_RAW_DATA;
}

std::string RawData::Data() const
{
    if (this->data) {
        return std::string(this->data.get(), this->length);
    }
    return "";
}

bool RawData::StorePacket(const unsigned char *buf, size_t len)
{
    if (buf == NULL || len == 0) {
        return false;
    }

    this->Reset();
    this->data = make_unique<char[]>(len);
    if (!this->data) {
        return false;
    }
    memcpy(this->data.get(), buf, len);
    this->length = len;
    return true;
}

bool RawData::StoreRaw(const unsigned char *buf, size_t len)
{
    if (buf == NULL || len == 0) {
        return false;
    }

    this->Reset();
    this->data = std::unique_ptr<char[]>((char *)buf);
    this->length = len;
    return true;
}

Json::Value RawData::Serialize() const
{
    Json::Value  root;
    if (this->data && this->length) {
        root[RAWDATA_SERIA_NAME_OPT_DATA] = "0x" + StringHelper::byte2basestr((const unsigned char *)this->data.get(), this->length, "", StringHelper::hex, 2);
    }
    return root;
}

bool RawData::UnSerialize(const Json::Value &in)
{
    if (!in.isMember(RAWDATA_SERIA_NAME_OPT_DATA) || !in[RAWDATA_SERIA_NAME_OPT_DATA].isString()) {
        return true;
    }    
    this->Reset();
    std::string data = in[RAWDATA_SERIA_NAME_OPT_DATA].asString();
    if (!data.size()) {
        return true;
    }
    const std::string *hexdata = &data;
    std::string tmpdata;
    if ((data.find("0x") != std::string::npos) || (data.find("0X") != std::string::npos)) {
        tmpdata = std::string(data, 2);
        hexdata = &tmpdata;
    }
    if (hexdata->size() & 1) {
        return false;
    }
    int buf_len = hexdata->size() / 2;
    char *buf = new char[buf_len];
    if (!buf) {
        return false;
    }
    if (StringHelper::hex2byte(hexdata->c_str(), (char *)buf, buf_len)) {
        this->StoreRaw((unsigned char *)buf, buf_len);
    }
    else {
        delete[]buf;
        buf = NULL;
    }
    return true;
}