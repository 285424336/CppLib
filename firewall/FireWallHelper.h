#ifndef FIREWALL_HELPER_H_INCLUDED
#define FIREWALL_HELPER_H_INCLUDED

#include <string>
#include <netfw.h>
#include <atlbase.h>
#include <atlcom.h>

class FireWallHelper 
{
public:
    static FireWallHelper &GetInstance();

public:
    FireWallHelper(const FireWallHelper&) = delete;
    FireWallHelper& operator=(const FireWallHelper&) = delete;
    bool AddRule(const std::wstring &wstrRuleName, const std::wstring &wstrAppPath);
    bool RemoveRule(const std::wstring &wstrRuleName);
    bool IsRuleExist(const std::wstring &wstrRuleName, const std::wstring &wstrAppPath);

private:
    FireWallHelper();
    virtual ~FireWallHelper();

private:
    bool Initialize();

private:
    CComPtr<INetFwPolicy2> m_pNetFwPolicy2;
    CComPtr<INetFwRules> m_pNetFwRules;
    CComPtr<INetFwRule>  m_pNetFwRule;
    CComPtr<INetFwRule2> m_pNetFwRule2;

private:
    static FireWallHelper instance;
};

#endif
