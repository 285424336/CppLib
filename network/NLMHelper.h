#ifndef NLM_HELPER_H_INCLUDED
#define NLM_HELPER_H_INCLUDED

#include <atlbase.h>
#include <atlcom.h>
#include <netlistmgr.h>
#include <string>
#include <vector>
#include "NetworkInfoHelper.h"

class CNLMHelper
{
public:
    typedef void(*NlMCallBack)(bool ev_connect);

private:
    class CoNetworkEventHandler :
        public INetworkListManagerEvents
    {
    public:
        static bool CreateInstance(NlMCallBack fnCb, IUnknown** pIFace)
        {
            CoNetworkEventHandler *instance = new (std::nothrow) CoNetworkEventHandler(fnCb);
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

    public:
        CoNetworkEventHandler(NlMCallBack fnCb) : m_lRefCnt(0), m_dwCookie(0), m_fnCb(fnCb) {}
        virtual ~CoNetworkEventHandler(void) {}
        STDMETHODIMP QueryInterface(REFIID riid, void** pIFace);
        STDMETHODIMP_(ULONG) AddRef();
        STDMETHODIMP_(ULONG) Release();
        STDMETHODIMP ConnectivityChanged(NLM_CONNECTIVITY NewConnectivity);

    private:
        long m_lRefCnt;
        DWORD m_dwCookie;
        NlMCallBack m_fnCb;
    };

public:
	static CNLMHelper& GetInstance() 
    {
        static CNLMHelper m_self;
        return m_self;
    };
    /**
    *regiest the callback for the network changing event
    *fnCb[in] callback function
    *return true|false
    *note only the last call will be registed, even if you call this function again and again
    *the callback will be called in private thread, so you should make sure the sync yourself
    */
	bool RegistNetworkChangeCallback(NlMCallBack fnCb);
    /**
    *unregiest the callback for the network changing event
    */
    void UnRegistNetworkChangeCallback();

private:
	CNLMHelper(void):m_pNLM(NULL), m_pUnkSink(NULL), m_dwCookie(0), m_is_co_init(false){}
    virtual ~CNLMHelper(void)
    {
        UnRegistNetworkChangeCallback();
    }

private:
	CComPtr <INetworkListManager> m_pNLM;
	CComPtr <IConnectionPoint> m_pConnPt;
    IUnknown *m_pUnkSink;
	DWORD m_dwCookie;
    bool m_is_co_init;
};
#endif
