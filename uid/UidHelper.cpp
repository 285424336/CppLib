#include <iostream>
#include "UidHelper.h"

#if defined(_MSC_VER)
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Rpcrt4.lib")
#elif defined(__GNUC__)
#include <file/FileHelper.h>
#define UUID_FILE_PATH "/proc/sys/kernel/random/uuid"
#else
#error unsupported compiler
#endif

std::string UidHelper::GenerateGUID()
{
#if defined(_MSC_VER)
    GUID guid = { 0 };
    if (S_OK != CoCreateGuid(&guid)) return "";
    return UUIDToString(guid);
#elif defined(__GNUC__)
    return FileHelper::GetFileContent(UUID_FILE_PATH);
#else
#error unsupported compiler
#endif
}

std::string UidHelper::GenerateUUID()
{
#if defined(_MSC_VER)
    UUID uuid = { 0 };
    if (RPC_S_OK != UuidCreate(&uuid)) return "";
    return UUIDToString(uuid);
#elif defined(__GNUC__)
    return FileHelper::GetFileContent(UUID_FILE_PATH);
#else
#error unsupported compiler
#endif
}

#if defined(_MSC_VER)
std::string UidHelper::UUIDToString(const UUID &uuid)
{
    std::string result;
    unsigned char *rpc_cstrUUID = NULL;
    if (RPC_S_OK != UuidToStringA(&uuid, &rpc_cstrUUID))
    {
        if (rpc_cstrUUID) RpcStringFreeA(&rpc_cstrUUID);
        return result;
    }
    result = reinterpret_cast<char*>(rpc_cstrUUID);
    RpcStringFreeA(&rpc_cstrUUID);
    return result;
}

UUID UidHelper::StringToUUID(const std::wstring &uuid)
{
    UUID result = { 0 };
    HRESULT hr = CLSIDFromString(uuid.c_str(), &result);
    if (!SUCCEEDED(hr))
    {
        return UUID();
    }
    return result;
}
#elif defined(__GNUC__)
#else
#error unsupported compiler
#endif