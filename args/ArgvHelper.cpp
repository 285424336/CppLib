#include "ArgvHelper.h"
#if defined(_MSC_VER)
#include <windows.h> 
#include <Dbghelp.h>
#pragma comment(lib,"dbghelp.lib")    
#elif defined(__GNUC__)
#include <cxxabi.h>
#define _CONSOLE
#else
#error unsupported compiler
#endif


#if defined(_MSC_VER)
/**
*get the friendly type name, for example demangle(typeid(int).name())
*name(in): type name
*/
std::string ArgvHelper::demangle(const std::string &name)
{
    CHAR szUndecorateName[256];
    memset(szUndecorateName, 0, 256);
    UnDecorateSymbolName(name.c_str(), szUndecorateName, 256, 0);
    return szUndecorateName;
}
#elif defined(__GNUC__)
/**
*get the friendly type name, for example demangle(typeid(int).name())
*name(in): type name
*/
std::string ArgvHelper::demangle(const std::string &name)
{
    int status = 0;
    char *p = abi::__cxa_demangle(name.c_str(), 0, 0, &status);
    std::string ret(p);
    free(p);
    return ret;
}
#else
#error unsupported compiler
#endif