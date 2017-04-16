#include <iostream>
#include "UidHelper.h"

#ifdef WIN32
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Rpcrt4.lib")
#else
//need use gun compile flag -luuid and install uuid-dev
#endif // WIN32

std::string UidHelper::GenerateGUID()
{
    std::string result;
    GUID guid = { 0 };
#ifdef WIN32
    if (S_OK != CoCreateGuid(&guid)) return result;
#else
    uuid_generate(guid);
#endif // WIN32
    return UUIDToString(guid);
}

std::string UidHelper::GenerateUUID()
{
    std::string result;
    UUID uuid = { 0 };
#ifdef WIN32
    if (RPC_S_OK != UuidCreate(&uuid)) return result;
#else
    uuid_generate(uuid);
#endif // WIN32
    return UUIDToString(uuid);
}

std::string UidHelper::UUIDToString(const UUID &uuid)
{
    std::string result;
#ifdef WIN32
    unsigned char *rpc_cstrUUID = NULL;
    if (RPC_S_OK != UuidToStringA(&uuid, &rpc_cstrUUID))
    {
        if (rpc_cstrUUID) RpcStringFreeA(&rpc_cstrUUID);
        return result;
    }
    result = reinterpret_cast<char*>(rpc_cstrUUID);
    RpcStringFreeA(&rpc_cstrUUID);
#else
    char buf[64] = { 0 };
    uuid_unparse(uuid, buf);
    result = buf;
#endif
    return std::move(result);
}