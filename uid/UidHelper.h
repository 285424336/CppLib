#ifndef UID_HELPER_H_INCLUDED
#define UID_HELPER_H_INCLUDED

#include <string>
#if defined(_MSC_VER)
#include <ShlObj.h>
#elif defined(__GNUC__)
#else
#error unsupported compiler
#endif

#if defined(_MSC_VER)
    using UUID = uuid_t;
    using GUID = uuid_t;
#elif defined(__GNUC__)
#else
#error unsupported compiler
#endif

class UidHelper
{
public:
    /**
    *generate the Globals Unique Identifiers
    */
    static std::string GenerateGUID();
    /**
    *generate the Universally Unique Identifier
    */
    static std::string GenerateUUID();
#if defined(_MSC_VER)
    /**
    *convert the uid to string
    *uuid(in): the GUID or UUID
    */
    static std::string UUIDToString(const UUID &uuid);
    /**
    *convert the string to uuid
    *uuid(in): the GUID string
    */
    static UUID StringToUUID(const std::wstring &uuid);
#elif defined(__GNUC__)
#else
#error unsupported compiler
#endif
};

#endif