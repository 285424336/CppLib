#include "NLMHelper.h"

bool CNLMHelper::RegistNetworkChangeCallback(NlMCallBack fnCb )
{
    HRESULT hr;

    if (m_is_co_init == false)
    {
        ::CoInitializeEx(NULL, COINIT_MULTITHREADED);
        m_is_co_init = true;
    }

    if (m_pNLM)
    {
        m_pNLM = NULL;
    }

    hr = m_pNLM.CoCreateInstance(CLSID_NetworkListManager);
	if (FAILED(hr))
	{
		return false;
	}

    if (m_pUnkSink)
    {
        m_pUnkSink->Release();
        m_pUnkSink = NULL;
    }

	if (false == CoNetworkEventHandler::CreateInstance(fnCb, &m_pUnkSink))
	{
		return false;
	}

	CComPtr<IConnectionPointContainer> pCPC;
	hr = m_pNLM->QueryInterface(IID_IConnectionPointContainer, (void**)&pCPC);
	if (FAILED(hr))
	{
		return false;
	}

    if (m_pConnPt)
    {
        m_pConnPt->Unadvise(m_dwCookie);
        m_pConnPt = NULL;
    }

    hr = pCPC->FindConnectionPoint(IID_INetworkListManagerEvents, &m_pConnPt);
    if (FAILED(hr))
    {
        return false;
    }

    hr = m_pConnPt->Advise(m_pUnkSink, &m_dwCookie);
    if (FAILED(hr))
    {
        return false;
    }

	return true;
}

void CNLMHelper::UnRegistNetworkChangeCallback()
{
    if (m_pConnPt)
    {
        m_pConnPt->Unadvise(m_dwCookie);
        m_pConnPt = NULL;
    }

    if (m_pUnkSink)
    {
        m_pUnkSink->Release();
        m_pUnkSink = NULL;
    }

    m_pNLM = NULL;

    if (m_is_co_init)
    {
        ::CoUninitialize();
        m_is_co_init = false;
    }
}


STDMETHODIMP CNLMHelper::CoNetworkEventHandler::QueryInterface(REFIID refIID, void** pIFace)
{
	*pIFace = NULL;
	if(refIID == IID_IUnknown || refIID == __uuidof(INetworkListManagerEvents))
	{
		*pIFace =  (IUnknown*)(INetworkListManagerEvents*)(this);
	}
	if (*pIFace == NULL)
	{
		return E_NOINTERFACE;
	}
	((IUnknown*)*pIFace)->AddRef();

	return S_OK;
}

STDMETHODIMP_(ULONG) CNLMHelper::CoNetworkEventHandler::AddRef()
{
	m_lRefCnt++;
	return m_lRefCnt;
}

STDMETHODIMP_(ULONG) CNLMHelper::CoNetworkEventHandler::Release()
{
	m_lRefCnt--;
	if(m_lRefCnt == 0) 
	{
		delete this;
		return (0);
	}
	return m_lRefCnt;
}

STDMETHODIMP  CNLMHelper::CoNetworkEventHandler::ConnectivityChanged( NLM_CONNECTIVITY NewConnectivity)
{
    if (m_fnCb==NULL) return S_OK;

    if ((NLM_CONNECTIVITY_DISCONNECTED != NewConnectivity)
        && !(NewConnectivity & NLM_CONNECTIVITY_IPV4_INTERNET)
        && !(NewConnectivity & NLM_CONNECTIVITY_IPV6_INTERNET)
        && !(NewConnectivity & NLM_CONNECTIVITY_IPV6_LOCALNETWORK))
    {
        return S_OK;
    }

    bool is_network_changed = false;
    NetworkInfoHelper::GetInstance().UpadteNetworkInfo(is_network_changed);
    if (!is_network_changed) return S_OK;

    if (!NetworkInfoHelper::GetInstance().GetPreNetworkGatewayMac().empty() && NetworkInfoHelper::GetInstance().GetGatewayMac().empty())
    {
        // the network off
        m_fnCb(false);
    }

    if (NetworkInfoHelper::GetInstance().GetPreNetworkGatewayMac().empty() && !NetworkInfoHelper::GetInstance().GetGatewayMac().empty())
    {
        // the network on
        m_fnCb(true);
    }

    if (!NetworkInfoHelper::GetInstance().GetPreNetworkGatewayMac().empty() && !NetworkInfoHelper::GetInstance().GetGatewayMac().empty())
    {
        //the network change
        m_fnCb(false);
        m_fnCb(true);
    }
    return S_OK;
} 

