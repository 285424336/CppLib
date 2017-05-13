#include <iostream>
#include "UidHelper.h"

#if defined(_MSC_VER)
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Rpcrt4.lib")
#elif defined(__GNUC__)
//need use gun compile flag -luuid and install uuid-dev
#else
#error unsupported compiler
#endif

std::string UidHelper::GenerateGUID()
{
    std::string result;
    GUID guid = { 0 };
#if defined(_MSC_VER)
    if (S_OK != CoCreateGuid(&guid)) return result;
#elif defined(__GNUC__)
    uuid_generate(guid);
#else
#error unsupported compiler
#endif
    return UUIDToString(guid);
}

std::string UidHelper::GenerateUUID()
{
    std::string result;
    UUID uuid = { 0 };
#if defined(_MSC_VER)
    if (RPC_S_OK != UuidCreate(&uuid)) return result;
#elif defined(__GNUC__)
    uuid_generate(uuid);
#else
#error unsupported compiler
#endif
    return UUIDToString(uuid);
}

std::string UidHelper::UUIDToString(const UUID &uuid)
{
    std::string result;
#if defined(_MSC_VER)
    unsigned char *rpc_cstrUUID = NULL;
    if (RPC_S_OK != UuidToStringA(&uuid, &rpc_cstrUUID))
    {
        if (rpc_cstrUUID) RpcStringFreeA(&rpc_cstrUUID);
        return result;
    }
    result = reinterpret_cast<char*>(rpc_cstrUUID);
    RpcStringFreeA(&rpc_cstrUUID);
#elif defined(__GNUC__)
    char buf[64] = { 0 };
    uuid_unparse(uuid, buf);
    result = buf;
#else
#error unsupported compiler
#endif
    return std::move(result);
}

UUID UidHelper::StringToUUID(const std::wstring &uuid)
{
    UUID result = { 0 };
#if defined(_MSC_VER)
    HRESULT hr = CLSIDFromString(uuid.c_str(), &result);
    if (!SUCCEEDED(hr))
    {
        return UUID();
    }
#elif defined(__GNUC__)
#else
#error unsupported compiler
#endif
    return result;
}