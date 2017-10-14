#include "FireWallHelper.h"
#include <windows.h>
#include <strsafe.h>

FireWallHelper FireWallHelper::instance;

FireWallHelper& FireWallHelper::GetInstance()
{
    return instance;
}

FireWallHelper::FireWallHelper() : m_pNetFwPolicy2(NULL), m_pNetFwRules(NULL), m_pNetFwRule(NULL), m_pNetFwRule2(NULL)
{
}

FireWallHelper::~FireWallHelper()
{
    m_pNetFwPolicy2 = NULL;
    m_pNetFwRules = NULL;
    m_pNetFwRule = NULL;
    m_pNetFwRule2 = NULL;
    CoUninitialize();
}

bool FireWallHelper::Initialize()
{
    if (m_pNetFwPolicy2) {
        return true;
    }
    CoInitialize(0);
    HRESULT hr = m_pNetFwPolicy2.CoCreateInstance(__uuidof(NetFwPolicy2),NULL,CLSCTX_INPROC_SERVER);
    if (FAILED(hr))
    {
        return false;
    }
    return true;
}

bool FireWallHelper::AddRule(const std::wstring &wstrRuleName, const std::wstring &wstrAppPath)
{
    if (IsRuleExist(wstrRuleName, wstrAppPath)) {
        return true;
    }
    if (!Initialize()) {
        return false;
    }
    HRESULT hr = S_OK;
    if (NULL == m_pNetFwRules) {
        hr = m_pNetFwPolicy2->get_Rules(&m_pNetFwRules);
        if (FAILED(hr)) {
            return false;
        }
    }
    if (m_pNetFwRule) {
        m_pNetFwRule = NULL;
    }
    hr = m_pNetFwRule.CoCreateInstance(__uuidof(NetFwRule), NULL, CLSCTX_INPROC_SERVER);
    if (FAILED(hr)){
        return false;
    }
    hr = m_pNetFwRule->put_Name(BSTR(wstrRuleName.c_str()));
    if (FAILED(hr)) {
        return false;
    }
    hr = m_pNetFwRule->put_Grouping(BSTR(wstrRuleName.c_str()));
    if (FAILED(hr)) {
        return false;
    }
    hr = m_pNetFwRule->put_Description(BSTR(wstrRuleName.c_str()));
    if (FAILED(hr)){
        return false;
    }
    hr = m_pNetFwRule->put_Action(NET_FW_ACTION_ALLOW);
    if (FAILED(hr)) {
        return false;
    }
    hr = m_pNetFwRule->put_ApplicationName(BSTR(wstrAppPath.c_str()));
    if (FAILED(hr)) {
        return false;
    }
    hr = m_pNetFwRule->put_Protocol(NET_FW_IP_PROTOCOL_ANY);
    if (FAILED(hr)) {
        return false;
    }
    hr = m_pNetFwRule->put_Profiles(NET_FW_PROFILE2_DOMAIN | NET_FW_PROFILE2_PRIVATE | NET_FW_PROFILE2_PUBLIC);
    if (FAILED(hr)) {
        return false;
    }
    hr = m_pNetFwRule->put_Enabled(VARIANT_TRUE);
    if (FAILED(hr)) {
        return false;
    }
    if (m_pNetFwRule2) {
        m_pNetFwRule2 = NULL;
    }
    if (SUCCEEDED(m_pNetFwRule->QueryInterface(__uuidof(INetFwRule2), (void**)&m_pNetFwRule2))) {
        hr = m_pNetFwRule2->put_EdgeTraversalOptions(NET_FW_EDGE_TRAVERSAL_TYPE_DEFER_TO_APP);
        if (FAILED(hr))
        {
            return false;
        }
    }
    else
    {
        hr = m_pNetFwRule->put_EdgeTraversal(VARIANT_TRUE);
        if (FAILED(hr)) {
            return false;
        }
    }
    hr = m_pNetFwRules->Add(m_pNetFwRule);
    if (FAILED(hr)) {
        return false;
    }
    return true;
}

bool FireWallHelper::RemoveRule(const std::wstring &wstrRuleName)
{
    if (!Initialize()) {
        return false;
    }
    HRESULT hr = S_OK;
    if (NULL == m_pNetFwRules) {
        hr = m_pNetFwPolicy2->get_Rules(&m_pNetFwRules);
        if (FAILED(hr)) {
            return false;
        }
    }
    hr = m_pNetFwRules->Remove(BSTR(wstrRuleName.c_str()));
    if (FAILED(hr)) {
        return false;
    }
    return true;
}

bool FireWallHelper::IsRuleExist(const std::wstring &wstrRuleName, const std::wstring &wstrAppPath)
{
    if (!Initialize()) {
        return false;
    }
    HRESULT hr = S_OK;
    if (NULL == m_pNetFwRules) {
        hr = m_pNetFwPolicy2->get_Rules(&m_pNetFwRules);
        if (FAILED(hr)) {
            return false;
        }
    }
    CComPtr<INetFwRule> pNetFwRule;
    hr = m_pNetFwRules->Item(BSTR(wstrRuleName.c_str()), &pNetFwRule);
    if (FAILED(hr)) {
        return false;
    }
    BSTR app_path;
    hr = pNetFwRule->get_ApplicationName(&app_path);
    if (FAILED(hr)) {
        return false;
    }
    if (wstrAppPath != app_path) {
        return false;
    }
    return true;
}