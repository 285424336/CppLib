#include "WMIHelper.h"

#include <objbase.h>
#pragma comment(lib,"wbemuuid.lib")

bool CSink::CreateInstance(IUnknown** pIFace, std::function<HRESULT(CComPtr<IWbemClassObject>)> f)
{
    CSink *instance = new (std::nothrow) CSink(f);
    if (NULL == instance)
    {
        return false;
    }

    if (FAILED(instance->QueryInterface(IID_IUnknown, (void**)pIFace)))
    {
        return false;
    }
    return true;
}

CSink::CSink(std::function<HRESULT(CComPtr<IWbemClassObject>)> f) : m_f(f), m_lRef(0), m_bDone(false)
{
}

CSink::~CSink(void)
{
}

ULONG STDMETHODCALLTYPE CSink::AddRef()
{
    return InterlockedIncrement(&m_lRef);
}

ULONG STDMETHODCALLTYPE CSink::Release()
{
    LONG lRef = InterlockedDecrement(&m_lRef);
    if (0 == lRef) {
        delete this;
    }
    return lRef;
}

HRESULT STDMETHODCALLTYPE CSink::QueryInterface(REFIID riid, void** ppv)
{
    if (IID_IUnknown == riid || IID_IWbemObjectSink == riid) {
        *ppv = (IWbemObjectSink*) this;
        AddRef();
        return WBEM_S_NO_ERROR;
    }
    return E_NOINTERFACE;
}

HRESULT STDMETHODCALLTYPE CSink::Indicate(LONG lObjectCount, IWbemClassObject __RPC_FAR* __RPC_FAR* apObjArray)
{
    for (long i = 0; i < lObjectCount; i++)
    {
        CComPtr<IWbemClassObject> pObj = apObjArray[i];
        if (m_f)
        {
            m_f(pObj);
        }
    }

    return WBEM_NO_ERROR;
}

HRESULT STDMETHODCALLTYPE CSink::SetStatus(LONG lFlags, HRESULT hResult, BSTR strParam, IWbemClassObject __RPC_FAR* pObjParam)
{
    switch (lFlags) {
    case WBEM_STATUS_COMPLETE:
    case WBEM_STATUS_REQUIREMENTS:
    case WBEM_STATUS_PROGRESS:
    default:
        break;
    }
    return WBEM_S_NO_ERROR;
}

WMIHelper::WMIHelper(const std::wstring &wstrNamespace) : m_wstrNamespace(wstrNamespace), m_pSvc(NULL)
{
    InitialCom();
}

WMIHelper::~WMIHelper()
{
    m_pSvc = NULL;
    CoUninitialize();
}

HRESULT WMIHelper::InitialCom()
{
    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (!SUCCEEDED(hr) && !(RPC_E_CHANGED_MODE == hr))
    {
        return hr;
    }
    return NOERROR;
}

HRESULT WMIHelper::SetComSecLevels()
{
    // Set general COM security levels --------------------------
    // Note: If you are using Windows 2000, you must specify -
    // the default authentication credentials for a user by using
    // a SOLE_AUTHENTICATION_LIST structure in the pAuthList ----
    // parameter of CoInitializeSecurity ------------------------

    HRESULT hr = CoInitializeSecurity(
        NULL,
        -1,                          // COM negotiates service
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
        RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities 
        NULL                         // Reserved
    );
    if (SUCCEEDED(hr) || RPC_E_TOO_LATE == hr)
    {
        return NOERROR;
    }
    return hr;
}

HRESULT WMIHelper::ObtainLocator2WMI(CComPtr<IWbemLocator>& pLoc)
{
    HRESULT hr = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID *)&pLoc);
    return hr;
}

HRESULT WMIHelper::Connect2WMI(CComPtr<IWbemLocator> pLoc)
{
    HRESULT hr = pLoc->ConnectServer(
        CComBSTR(m_wstrNamespace.c_str()),
        NULL, NULL, NULL, NULL, NULL, NULL, &m_pSvc);
    return hr;
}

HRESULT WMIHelper::SetProxySecLevels()
{
    HRESULT hr = CoSetProxyBlanket(
        m_pSvc,                        // Indicates the proxy to set
        RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx 
        RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx 
        NULL,                        // Server principal name 
        RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
        RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
        NULL,                        // client identity
        EOAC_NONE                    // proxy capabilities 
    );

    return hr;
}

bool WMIHelper::Connect()
{
    HRESULT hr = E_FAIL;
    bool ret = false;
    CComPtr<IWbemLocator> pLoc = NULL;

    do {
        hr = SetComSecLevels();
        if (FAILED((hr)))
        {
            break;
        }

        hr = ObtainLocator2WMI(pLoc);
        if (FAILED((hr)))
        {
            break;
        }

        hr = Connect2WMI(pLoc);
        if (FAILED((hr)))
        {
            break;
        }

        hr = SetProxySecLevels();
        if (FAILED((hr)))
        {
            break;
        }
        ret = true;
    } while (0);

    return ret;
}

WMIExecValue WMIHelper::CComVariant2WMIExecValue(const CComVariant& Value, const std::wstring &name)
{
    WMIExecValue tmp;
    switch (Value.vt) {
    case VT_BSTR:
    {
        tmp.properity = name;
        tmp.type = VT_BSTR;
        tmp.strVal = Value.bstrVal;
    }
    break;
    case VT_I1:
    case VT_I2:
    case VT_I4:
    case VT_I8:
    case VT_INT:
    {
        tmp.properity = name;
        tmp.type = VT_INT;
        tmp.intVal = Value.ullVal;
    }
    break;
    case VT_UI8:
    case VT_UI1:
    case VT_UI2:
    case VT_UI4:
    case VT_UINT:
    {
        tmp.properity = name;
        tmp.type = VT_UINT;
        tmp.uintVal = Value.ullVal;
    }
    break;
    case VT_BOOL:
    {
        tmp.properity = name;
        tmp.type = VT_BOOL;
        tmp.boolVal = Value.boolVal == -1;
    }
    break;
    default:
    {
        tmp.properity = name;
        tmp.type = Value.vt;
    }
    break;
    }
    return tmp;
}

HRESULT WMIHelper::ExecQuery(const std::wstring &wszWQLQuery, std::function<HRESULT(CComPtr<IWbemClassObject>)> f)
{
    if (m_pSvc == NULL)
    {
        return E_FAIL;
    }

    CComPtr<IEnumWbemClassObject> pEnumerator = NULL;
    HRESULT hr = m_pSvc->ExecQuery(
        CComBSTR("WQL"),
        CComBSTR(wszWQLQuery.c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if ((hr) != WBEM_S_NO_ERROR)
    {
        return E_FAIL;
    }

    while (pEnumerator)
    {
        CComPtr<IWbemClassObject> pclsObj = NULL;
        ULONG uReturn = 0;
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if ((S_OK != hr) || (0 == uReturn) || (NULL == pclsObj))
        {
            return E_FAIL;
        }

        hr = f(pclsObj);
        if (S_OK == hr)
        {
            return S_OK;
        }
    }
    return E_FAIL;
}

bool WMIHelper::QueryStr(std::wstring &result, const std::wstring &wszWQLQuery, const std::wstring &wszProperty)
{
    HRESULT hr = ExecQuery(wszWQLQuery, [this, &result, &wszProperty](CComPtr<IWbemClassObject> pclsObj)
        {
            CComVariant vtClass;
            HRESULT hr = pclsObj->Get(wszProperty.c_str(), 0, &vtClass, NULL, NULL);
            if ((hr) != WBEM_S_NO_ERROR)
            {
                return S_FALSE;
            }
            switch (vtClass.vt) {
            case VT_BSTR:
            {
                result = vtClass.bstrVal;
                return S_OK;
            }
            break;
            default:
                break;
            }
            return S_FALSE;
        });

    return SUCCEEDED(hr);
}

bool WMIHelper::QueryInt(long long &result, const std::wstring &wszWQLQuery, const std::wstring &wszProperty)
{
    HRESULT hr = ExecQuery(wszWQLQuery, [this, &result, &wszProperty](CComPtr<IWbemClassObject> pclsObj)
        {
            CComVariant vtClass;
            HRESULT hr = pclsObj->Get(wszProperty.c_str(), 0, &vtClass, NULL, NULL);
            if ((hr) != WBEM_S_NO_ERROR)
            {
                return S_FALSE;
            }
            switch (vtClass.vt) {
            case VT_I1:
            case VT_I2:
            case VT_I4:
            case VT_I8:
            case VT_INT:
            {
                result = vtClass.llVal;
                return S_OK;
            }
            break;
            default:
                break;
            }
            return S_FALSE;
        });

    return SUCCEEDED(hr);
}

bool WMIHelper::QueryUnInt(unsigned long long &result, const std::wstring &wszWQLQuery, const std::wstring &wszProperty)
{
    HRESULT hr = ExecQuery(wszWQLQuery, [this, &result, &wszProperty](CComPtr<IWbemClassObject> pclsObj)
        {
            CComVariant vtClass;
            HRESULT hr = pclsObj->Get(wszProperty.c_str(), 0, &vtClass, NULL, NULL);
            if ((hr) != WBEM_S_NO_ERROR)
            {
                return S_FALSE;
            }
            switch (vtClass.vt) {
            case VT_UI8:
            case VT_UI1:
            case VT_UI2:
            case VT_UI4:
            case VT_UINT:
            {
                result = vtClass.ullVal;
                return S_OK;
            }
            break;
            default:
                break;
            }
            return S_FALSE;
        });

    return SUCCEEDED(hr);
}

bool WMIHelper::QueryBool(bool &result, const std::wstring &wszWQLQuery, const std::wstring &wszProperty)
{
    HRESULT hr = ExecQuery(wszWQLQuery, [this, &result, &wszProperty](CComPtr<IWbemClassObject> pclsObj)
        {
            CComVariant vtClass;
            HRESULT hr = pclsObj->Get(wszProperty.c_str(), 0, &vtClass, NULL, NULL);
            if ((hr) != WBEM_S_NO_ERROR)
            {
                return S_FALSE;
            }
            switch (vtClass.vt) {
            case VT_BOOL:
            {
                result = vtClass.boolVal == -1; 
                return S_OK;
            }
            break;
            default:
                break;
            }
            return S_FALSE;
        });

    return SUCCEEDED(hr);
}

bool WMIHelper::QueryEnum(std::vector<WMIExecValue> &result, const std::wstring &wszWQLQuery)
{
    HRESULT hr = ExecQuery(wszWQLQuery, [this, &result](CComPtr<IWbemClassObject> pclsObj)
        {
            HRESULT hr = pclsObj->BeginEnumeration(WBEM_FLAG_LOCAL_ONLY);
            if ((hr) != WBEM_S_NO_ERROR)
            {
                return S_FALSE;
            }

            do {
                CComBSTR bstrName;
                CComVariant Value;
                CIMTYPE type;
                LONG lFlavor = 0;
                hr = pclsObj->Next(0, &bstrName, &Value, &type, &lFlavor);
                if ((hr) != WBEM_S_NO_ERROR)
                {
                    break;
                }
                result.emplace_back(CComVariant2WMIExecValue(Value, std::wstring(bstrName)));
            } while (WBEM_S_NO_ERROR == hr);
            pclsObj->EndEnumeration();
            return S_FALSE;
        });

    return SUCCEEDED(hr);
}

HRESULT WMIHelper::NotificationExecQuery(const std::wstring &wszWQLQuery, HANDLE stopEvent, int millTimeOut, std::function<HRESULT(CComPtr<IWbemClassObject>)> f)
{
    HRESULT hr = WBEM_S_FALSE;

    if (m_pSvc == NULL)
    {
        return WBEM_S_FALSE;
    }

    CComPtr<IUnknown> pSink = NULL;
    CSink::CreateInstance(&pSink, f);
    if (pSink == NULL)
    {
        return WBEM_S_FALSE;
    }

    CComPtr<IUnsecuredApartment> pUnsecApp = NULL;
    hr = CoCreateInstance(CLSID_UnsecuredApartment, NULL, CLSCTX_LOCAL_SERVER, IID_IUnsecuredApartment, (void**)&pUnsecApp);
    if ((hr) != WBEM_S_NO_ERROR)
    {
        return WBEM_S_FALSE;
    }

    CComPtr<IUnknown> pStubUnk = NULL;
    pUnsecApp->CreateObjectStub(pSink, &pStubUnk);
    if (pStubUnk == NULL)
    {
        return WBEM_S_FALSE;
    }

    CComPtr<IWbemObjectSink> pStubSink = NULL;
    pStubUnk->QueryInterface(IID_IWbemObjectSink, (void**)&pStubSink);
    if (pStubSink == NULL)
    {
        return WBEM_S_FALSE;
    }

    hr = m_pSvc->ExecNotificationQueryAsync(
        CComBSTR("WQL"),
        CComBSTR(wszWQLQuery.c_str()),
        WBEM_FLAG_SEND_STATUS,
        NULL,
        pStubSink);

    if ((hr) != WBEM_S_NO_ERROR)
    {
        return WBEM_S_FALSE;
    }

    if (NULL != stopEvent)
    {
        WaitForSingleObject(stopEvent, millTimeOut);
    }

    m_pSvc->CancelAsyncCall(pStubSink);
    return WBEM_S_NO_ERROR;
}

bool WMIHelper::NotificationQueryStr(std::wstring &result, const std::wstring &wszWQLQuery, const std::wstring &wszProperty, int millTimeOut)
{
    HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (hEvent == NULL)
    {
        return false;
    }

    HRESULT hr = NotificationExecQuery(wszWQLQuery, hEvent, millTimeOut, [this, &result, &wszProperty, hEvent](CComPtr<IWbemClassObject> pclsObj)
        {
            CComVariant vtClass;
            HRESULT hr = pclsObj->Get(wszProperty.c_str(), 0, &vtClass, NULL, NULL);
            if ((hr) != WBEM_S_NO_ERROR)
            {
                return S_FALSE;
            }
            switch (vtClass.vt) {
            case VT_BSTR:
            {
                result = vtClass.bstrVal;
                SetEvent(hEvent);
                return S_OK;
            }
            break;
            default:
                break;
            }
            return S_FALSE;
        });

    CloseHandle(hEvent);
    return SUCCEEDED(hr);
}

bool WMIHelper::NotificationQueryInt(long long &result, const std::wstring &wszWQLQuery, const std::wstring &wszProperty, int millTimeOut)
{
    HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (hEvent == NULL)
    {
        return false;
    }

    HRESULT hr = NotificationExecQuery(wszWQLQuery, hEvent, millTimeOut, [this, &result, &wszProperty, hEvent](CComPtr<IWbemClassObject> pclsObj)
        {
            CComVariant vtClass;
            HRESULT hr = pclsObj->Get(wszProperty.c_str(), 0, &vtClass, NULL, NULL);
            if ((hr) != WBEM_S_NO_ERROR)
            {
                return S_FALSE;
            }
            switch (vtClass.vt) {
            case VT_I1:
            case VT_I2:
            case VT_I4:
            case VT_I8:
            case VT_INT:
            {
                result = vtClass.llVal;
                SetEvent(hEvent);
                return S_OK;
            }
            break;
            default:
                break;
            }
            return S_FALSE;
        });

    CloseHandle(hEvent);
    return SUCCEEDED(hr);
}

bool WMIHelper::NotificationQueryUnInt(unsigned long long &result, const std::wstring &wszWQLQuery, const std::wstring &wszProperty, int millTimeOut)
{
    HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (hEvent == NULL)
    {
        return false;
    }

    HRESULT hr = NotificationExecQuery(wszWQLQuery, hEvent, millTimeOut, [this, &result, &wszProperty, hEvent](CComPtr<IWbemClassObject> pclsObj)
        {
            CComVariant vtClass;
            HRESULT hr = pclsObj->Get(wszProperty.c_str(), 0, &vtClass, NULL, NULL);
            if ((hr) != WBEM_S_NO_ERROR)
            {
                return S_FALSE;
            }
            switch (vtClass.vt) {
            case VT_UI8:
            case VT_UI1:
            case VT_UI2:
            case VT_UI4:
            case VT_UINT:
            {
                result = vtClass.ullVal;
                SetEvent(hEvent);
                return S_OK;
            }
            break;
            default:
                break;
            }
            return S_FALSE;
        });

    CloseHandle(hEvent);
    return SUCCEEDED(hr);
}

bool WMIHelper::NotificationQueryBool(bool &result, const std::wstring &wszWQLQuery, const std::wstring &wszProperty, int millTimeOut)
{
    HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (hEvent == NULL)
    {
        return false;
    }

    HRESULT hr = NotificationExecQuery(wszWQLQuery, hEvent, millTimeOut, [this, &result, &wszProperty, hEvent](CComPtr<IWbemClassObject> pclsObj)
        {
            CComVariant vtClass;
            HRESULT hr = pclsObj->Get(wszProperty.c_str(), 0, &vtClass, NULL, NULL);
            if ((hr) != WBEM_S_NO_ERROR)
            {
                return S_FALSE;
            }
            switch (vtClass.vt) {
            case VT_BOOL:
            {
                result = vtClass.boolVal == -1;
                SetEvent(hEvent);
                return S_OK;
            }
            break;
            default:
                break;
            }
            return S_FALSE;
        });

    CloseHandle(hEvent);
    return SUCCEEDED(hr);
}

bool WMIHelper::NotificationQueryEnum(std::vector<WMIExecValue> &result, const std::wstring &wszWQLQuery, int millTimeOut)
{
    HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (hEvent == NULL)
    {
        return false;
    }

    HRESULT hr = NotificationExecQuery(wszWQLQuery, hEvent, millTimeOut, [this, &result, hEvent](CComPtr<IWbemClassObject> pclsObj)
        {
            HRESULT hr = pclsObj->BeginEnumeration(WBEM_FLAG_LOCAL_ONLY);
            if ((hr) != WBEM_S_NO_ERROR)
            {
                return S_FALSE;
            }

            do {
                CComBSTR bstrName;
                CComVariant Value;
                CIMTYPE type;
                LONG lFlavor = 0;
                hr = pclsObj->Next(0, &bstrName, &Value, &type, &lFlavor);
                if ((hr) != WBEM_S_NO_ERROR)
                {
                    break;
                }
                result.emplace_back(CComVariant2WMIExecValue(Value, std::wstring(bstrName)));
            } while (WBEM_S_NO_ERROR == hr);
            pclsObj->EndEnumeration();
            return S_FALSE;
        });

    CloseHandle(hEvent);
    return SUCCEEDED(hr);
}

bool WMIHelper::ExecMethod(WMIExecValue &execRet, const std::wstring& wstrClass, const std::wstring& wstrMethod, const std::wstring& wstrRetName, const std::map<std::wstring, CComVariant>& params)
{
    if (m_pSvc == NULL)
    {
        return false;
    }

    HRESULT hr = WBEM_S_FALSE;
    do {
        if (wstrClass.empty())
        {
            break;
        }

        CComBSTR bstrClassName = wstrClass.c_str();
        CComPtr<IWbemClassObject> spClass = NULL;
        hr = m_pSvc->GetObjectW(bstrClassName, 0, NULL, &spClass, NULL);
        if (FAILED(hr) || !spClass) 
        {
            break;
        }

        CComBSTR bstrMethodName = wstrMethod.c_str();
        CComPtr<IWbemClassObject> spInParamsDefinition = NULL;
        hr = spClass->GetMethod(bstrMethodName, 0, &spInParamsDefinition, NULL);
        if (FAILED(hr))
        {
            break;
        }

        CComPtr<IWbemClassObject> spParamsInstance = NULL;
        if (spInParamsDefinition) 
        {
            hr = spInParamsDefinition->SpawnInstance(0, &spParamsInstance);
            if (FAILED(hr) || !spParamsInstance) 
            {
                break;
            }

            for (auto it = params.begin(); it != params.end(); it++) 
            {
                if (!it->first.empty()) 
                {
                    CComVariant value = it->second;
                    hr = spParamsInstance->Put(it->first.c_str(), 0, &value, 0);
                }
            }
        }

        CComPtr<IWbemClassObject> spOutParams = NULL;
        hr = m_pSvc->ExecMethod(bstrClassName, bstrMethodName, 0, NULL, spParamsInstance, &spOutParams, NULL);
        if (SUCCEEDED(hr) && !wstrRetName.empty())
        {
            CComVariant varRet;
            hr = spOutParams->Get(CComBSTR(wstrRetName.c_str()), 0, &varRet, NULL, 0);
            if (SUCCEEDED(hr))
            {
                execRet = CComVariant2WMIExecValue(varRet, wstrRetName);
            }
        }
    } while (0);

    return SUCCEEDED(hr);
}
