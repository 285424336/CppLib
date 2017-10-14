#ifndef RAW_DATA_H_INCLUDED
#define RAW_DATA_H_INCLUDED

#include "NetBase.h"

#define RAWDATA_SERIA_NAME_OPT_DATA "data"

class RawData : public NetBase 
{
public:
    RawData();
    ~RawData();
    void Reset();
    int ProtocolId() const;
    std::string Data() const;
    bool StorePacket(const unsigned char *buf, size_t len);
    /**
    *store the raw data, and will not make a copy, you should make sure the buf will not be delete, 
    *RawData class will take over the control of the life time
    */
    bool StoreRaw(const unsigned char *buf, size_t len);
    Json::Value Serialize() const;
    bool UnSerialize(const Json::Value &in);

private:
    std::unique_ptr<char[]> data;
};

#endif
