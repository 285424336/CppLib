#pragma once

#include <windows.h>
#include <comdef.h>
#include <wbemidl.h>

#include <atlbase.h>
#include <atlcom.h>
#include <string>
#include <functional>
#include <vector>
#include <map>
#include <iostream>
#include <mutex>

#define DEFALUT_WMI_NAMESPACE L"ROOT\\DEFAULT"
#define SECURITY_WMI_NAMESPACE L"ROOT\\SECURITY"
#define CIMV2_WMI_NAMESPACE L"ROOT\\CIMV2"

typedef struct
{
    std::wstring properity;
    int          type;
    std::wstring strVal;
    signed long long intVal;
    unsigned long long uintVal;
    bool         boolVal;

    bool IsStringType()
    {
        return type == VT_BSTR;
    }

    bool IsIntType()
    {
        return type == VT_INT;
    }

    bool IsUintType()
    {
        return type == VT_UINT;
    }

    bool IsBoolType()
    {
        return type == VT_BOOL;
    }
}WMIExecValue;

inline std::wostream& operator<<(std::wostream& out, const WMIExecValue& date)
{
    switch (date.type)
    {
    case VT_BSTR:
        out << "properity: " << date.properity << " type: " << date.type << " value: " << date.strVal;
        break;
    case VT_INT:
        out << "properity: " << date.properity << " type: " << date.type << " value: " << date.intVal;
        break;
    case VT_UINT:
        out << "properity: " << date.properity << " type: " << date.type << " value: " << date.uintVal;
        break;
    case VT_BOOL:
        out << "properity: " << date.properity << " type: " << date.type << " value: " << date.boolVal;
        break;
    default:
        out << "properity: " << date.properity << " type: " << date.type;
        break;
    }
    return out;
}

class CSink : public IWbemObjectSink
{
public:
    static bool CreateInstance(IUnknown** pIFace, std::function<HRESULT(CComPtr<IWbemClassObject>)> f);

public:
    virtual ULONG STDMETHODCALLTYPE AddRef();
    virtual ULONG STDMETHODCALLTYPE Release();
    virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv);
    virtual HRESULT STDMETHODCALLTYPE Indicate(LONG lObjectCount, IWbemClassObject __RPC_FAR* __RPC_FAR* apObjArray);
    virtual HRESULT STDMETHODCALLTYPE SetStatus(LONG lFlags, HRESULT hResult, BSTR strParam, IWbemClassObject __RPC_FAR* pObjParam);

private:
    explicit CSink(std::function<HRESULT(CComPtr<IWbemClassObject>)> f);
    ~CSink();

private:
    std::function<HRESULT(CComPtr<IWbemClassObject>)> m_f;
    LONG m_lRef;
    bool m_bDone;
};

class WMIHelper
{
public:
    explicit WMIHelper(const std::wstring &wstrNamespace);
    virtual ~WMIHelper();
    /**
    *Connect function must be called first, before you do another actions
    */
    virtual bool Connect();
    /**
    *exec the query and get the specify string type property value
    *result(out) the result
    *wszWQLQuery(in) the query wql
    *wszProperty(in) the specify property
    *return true-success false-failed
    */
    virtual bool QueryStr(std::wstring &result, const std::wstring &wszWQLQuery, const std::wstring &wszProperty);
    /**
    *exec the query and get the specify string type property value
    *result(out) the result
    *wszWQLQuery(in) the query wql
    *wszProperty(in) the specify property
    *return true-success false-failed
    */
    virtual bool QueryStr(std::vector<std::wstring> &result, const std::wstring &wszWQLQuery, const std::wstring &wszProperty);
    /**
    *exec the query and get the specify int type property value
    *result(out) the result
    *wszWQLQuery(in) the query wql
    *wszProperty(in) the specify property
    *return true-success false-failed
    */
    virtual bool QueryInt(long long &result, const std::wstring &wszWQLQuery, const std::wstring &wszProperty);
    /**
    *exec the query and get the specify int type property value
    *result(out) the result
    *wszWQLQuery(in) the query wql
    *wszProperty(in) the specify property
    *return true-success false-failed
    */
    virtual bool QueryInt(std::vector<long long> &result, const std::wstring &wszWQLQuery, const std::wstring &wszProperty);
    /**
    *exec the query and get the specify uint type property value
    *result(out) the result
    *wszWQLQuery(in) the query wql
    *wszProperty(in) the specify property
    *return true-success false-failed
    */
    virtual bool QueryUnInt(unsigned long long &result, const std::wstring &wszWQLQuery, const std::wstring &wszProperty);
    /**
    *exec the query and get the specify uint type property value
    *result(out) the result
    *wszWQLQuery(in) the query wql
    *wszProperty(in) the specify property
    *return true-success false-failed
    */
    virtual bool QueryUnInt(std::vector<unsigned long long> &result, const std::wstring &wszWQLQuery, const std::wstring &wszProperty);
    /**
    *exec the query and get the specify bool type property value
    *result(out) the result
    *wszWQLQuery(in) the query wql
    *wszProperty(in) the specify property
    *return true-success false-failed
    */
    virtual bool QueryBool(bool &result, const std::wstring &wszWQLQuery, const std::wstring &wszProperty);
    /**
    *exec the query and get the specify bool type property value
    *result(out) the result
    *wszWQLQuery(in) the query wql
    *wszProperty(in) the specify property
    *return true-success false-failed
    */
    virtual bool QueryBool(std::vector<bool> &result, const std::wstring &wszWQLQuery, const std::wstring &wszProperty);
    /**
    *exec the query and enum all property value
    *result(out) the results
    *wszWQLQuery(in) the query wql
    *return true-success false-failed
    */
    virtual bool QueryEnum(std::vector<WMIExecValue> &result, const std::wstring &wszWQLQuery);
    /**
    *exec the query and get the specify string type property value,  NotificationQuery* can onlu exec notification wql
    *result(out) the result
    *wszWQLQuery(in) the query wql
    *wszProperty(in) the specify property
    *millTimeOut(in) the max exec timeout
    *return true-success false-failed
    *notification query wql format: SELECT * FROM [EventClass] WITHIN [interval] WHERE TargetInstance ISA [object] <AND TargetInstance.[property] > [value]>
    */
    virtual bool NotificationQueryStr(std::wstring &result, const std::wstring &wszWQLQuery, const std::wstring &wszProperty, int millTimeOut = 3000);
    /**
    *exec the query and get the specify int type property value,  NotificationQuery* can onlu exec notification wql
    *result(out) the result
    *wszWQLQuery(in) the query wql
    *wszProperty(in) the specify property
    *millTimeOut(in) the max exec timeout
    *return true-success false-failed
    *notification query wql format: SELECT * FROM [EventClass] WITHIN [interval] WHERE TargetInstance ISA [object] <AND TargetInstance.[property] > [value]>
    */
    virtual bool NotificationQueryInt(long long &result, const std::wstring &wszWQLQuery, const std::wstring &wszProperty, int millTimeOut = 3000);
    /**
    *exec the query and get the specify uint type property value,  NotificationQuery* can onlu exec notification wql
    *result(out) the result
    *wszWQLQuery(in) the query wql
    *wszProperty(in) the specify property
    *millTimeOut(in) the max exec timeout
    *return true-success false-failed
    *notification query wql format: SELECT * FROM [EventClass] WITHIN [interval] WHERE TargetInstance ISA [object] <AND TargetInstance.[property] > [value]>
    */
    virtual bool NotificationQueryUnInt(unsigned long long &result, const std::wstring &wszWQLQuery, const std::wstring &wszProperty, int millTimeOut = 3000);
    /**
    *exec the query and get the specify bool type property value,  NotificationQuery* can onlu exec notification wql
    *result(out) the result
    *wszWQLQuery(in) the query wql
    *wszProperty(in) the specify property
    *millTimeOut(in) the max exec timeout
    *return true-success false-failed
    *notification query wql format: SELECT * FROM [EventClass] WITHIN [interval] WHERE TargetInstance ISA [object] <AND TargetInstance.[property] > [value]>
    */
    virtual bool NotificationQueryBool(bool &result, const std::wstring &wszWQLQuery, const std::wstring &wszProperty, int millTimeOut = 3000);
    /**
    *exec the query and enum all property value,  NotificationQuery* can onlu exec notification wql
    *result(out) the results
    *wszWQLQuery(in) the query wql
    *millTimeOut(in) the max exec timeout
    *return true-success false-failed
    *notification query wql format: SELECT * FROM [EventClass] WITHIN [interval] WHERE TargetInstance ISA [object] <AND TargetInstance.[property] > [value]>
    */
    virtual bool NotificationQueryEnum(std::vector<WMIExecValue> &result, const std::wstring &wszWQLQuery, int millTimeOut = 3000);
    /**
    *exec the method and get the exec result
    *ret(out) the exec result
    *wstrClass(in) the class which contains the method
    *wstrMethod(in) the method
    *wstrRetName(in) the return value name , like L"ReturnValue"
    *params(in) the parameters used for the method
    *return true-success false-failed
    */
    virtual bool ExecMethod(WMIExecValue &ret, const std::wstring& wstrClass, const std::wstring& wstrMethod, const std::wstring& wstrRetName, const std::map<std::wstring, CComVariant>& params);

protected:
    virtual HRESULT InitialCom();
    virtual HRESULT SetComSecLevels();
    virtual HRESULT ObtainLocator2WMI(CComPtr<IWbemLocator>& pLoc);
    virtual HRESULT Connect2WMI(CComPtr<IWbemLocator> pLoc);
    virtual HRESULT SetProxySecLevels();
    virtual HRESULT ExecQuery(const std::wstring &wszWQLQuery, std::function<HRESULT(CComPtr<IWbemClassObject>)>);
    virtual HRESULT ExecQueryList(const std::wstring &wszWQLQuery, std::function<HRESULT(CComPtr<IWbemClassObject>)>);
    virtual HRESULT NotificationExecQuery(const std::wstring &wszWQLQuery, HANDLE stopEvent, int millTimeOut, std::function<HRESULT(CComPtr<IWbemClassObject>)>);
    virtual WMIExecValue CComVariant2WMIExecValue(const CComVariant& value, const std::wstring &name);

private:
    std::wstring m_wstrNamespace;
    CComPtr<IWbemServices> m_pSvc;
};

typedef enum {
    WMI_EASY_QUERY_STR_HOST_NAME = 0,
    WMI_EASY_QUERY_STR_MODEL = 1,
    WMI_EASY_QUERY_STR_VENDOR = 2,
    WMI_EASY_QUERY_STR_MANUFACTURER = 3,
    WMI_EASY_QUERY_STR_OS_VERSION = 4,
    WMI_EASY_QUERY_STR_CPU_VENDOR = 5,
    WMI_EASY_QUERY_STR_DISK_VENDOR = 6,
    WMI_EASY_QUERY_STR_MEMORY_MANUFACTURER = 7,
    WMI_EASY_QUERY_STR_NETWORK_ADAPTER_VENDOR = 8,
    WMI_EASY_QUERY_STR_MAX
}WMI_EASY_QUERY_STR;

typedef struct {
    WMI_EASY_QUERY_STR index;
    std::wstring wszNamespace;
    std::wstring wszQueryStatement;
    std::wstring wszWQLQueryClsObj;
    bool         is_volatile;
}WmiQueryObj;

class WMIEasyQuery
{
public:
    /**
    *get the string result of the object from wmi, if there exist more than one, only return the first one
    *index(in): the object you want to query
    *return result of the query
    */
    static std::wstring QueryStr(WMI_EASY_QUERY_STR index);
    /**
    *get the string results of the object from wmi, if there exist more than one, return all result
    *index(in): the object you want to query
    *return results of the query
    */
    static std::vector<std::wstring> QueryStrList(WMI_EASY_QUERY_STR index);

private:
    static bool Init();

private:
    WMIEasyQuery(const std::wstring &wszNamespace, const std::wstring &wszQueryStatement, const std::wstring &wszWQLQueryClsObj, bool is_volatile)
        : m_wszNamespace(wszNamespace), m_wszQueryStatement(wszQueryStatement), m_wszWQLQueryClsObj(wszWQLQueryClsObj), m_is_volatile(is_volatile), m_result(), m_result_list()
    {

    }

private:
    std::wstring m_wszNamespace;
    std::wstring m_wszQueryStatement;
    std::wstring m_wszWQLQueryClsObj;
    bool         m_is_volatile;
    std::wstring m_result;
    std::vector<std::wstring> m_result_list;

private:
    static bool                                       is_init;
    static std::map<WMI_EASY_QUERY_STR, std::shared_ptr<WMIEasyQuery>> str_query_map;
    static WmiQueryObj                                str_query_list[];
};