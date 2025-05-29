```
#include <windows.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <vector>
#pragma comment(lib, "wbemuuid.lib")
#include <iostream>

void QueryWMI(const BSTR className, const std::vector<std::wstring>& fields) {
    IWbemLocator* pLoc = nullptr;
    IWbemServices* pSvc = nullptr;
    IEnumWbemClassObject* pEnumerator = nullptr;

    HRESULT hres;

    // Khởi tạo COM nếu chưa
    CoInitializeEx(0, COINIT_MULTITHREADED);
    CoInitializeSecurity(NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);

    CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);

    pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"),
        NULL, NULL, 0, NULL, 0, 0, &pSvc);

    CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

    // Tạo câu truy vấn WQL
    std::wstring query = L"SELECT ";
    for (size_t i = 0; i < fields.size(); ++i) {
        query += fields[i];
        if (i != fields.size() - 1) query += L", ";
    }
    query += L" FROM ";
    query += className;

    pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t(query.c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL, &pEnumerator);

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;

    while (pEnumerator && pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn) == S_OK) {
        for (const auto& field : fields) {
            VARIANT vtProp;
            HRESULT hr = pclsObj->Get(field.c_str(), 0, &vtProp, 0, 0);
            if (SUCCEEDED(hr)) {
                std::wcout << field << L": ";
                if (vtProp.vt == VT_BSTR) std::wcout << vtProp.bstrVal;
                else if (vtProp.vt == VT_I4) std::wcout << vtProp.lVal;
                else if (vtProp.vt == VT_BOOL) std::wcout << (vtProp.boolVal ? L"True" : L"False");
                else if (vtProp.vt == VT_UI1) std::wcout << (int)vtProp.bVal;
                else std::wcout << L"[Unknown Type]";
                std::wcout << std::endl;
                VariantClear(&vtProp);
            }
        }
        std::wcout << L"-----------------------------------\n";
        pclsObj->Release();
    }

    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
}

int main() {
    std::wcout << L"\n==== [1] System Information ====\n";
    QueryWMI((BSTR)L"Win32_OperatingSystem", { L"Caption", L"OSArchitecture", L"Version", L"BuildNumber" });

    std::wcout << L"\n==== [2] CPU ====\n";
    QueryWMI((BSTR)L"Win32_Processor", { L"Name", L"NumberOfCores", L"MaxClockSpeed" });

    std::wcout << L"\n==== [3] BIOS ====\n";
    QueryWMI((BSTR)L"Win32_BIOS", { L"Manufacturer", L"SMBIOSBIOSVersion", L"ReleaseDate" });

    std::wcout << L"\n==== [4] RAM ====\n";
    QueryWMI((BSTR)L"Win32_PhysicalMemory", { L"Capacity", L"Speed" });

    std::wcout << L"\n==== [5] Logical Disks ====\n";
    QueryWMI((BSTR)L"Win32_LogicalDisk", { L"DeviceID", L"FileSystem", L"FreeSpace", L"Size", L"VolumeName" });

    std::wcout << L"\n==== [6] Network Adapter ====\n";
    QueryWMI((BSTR)L"Win32_NetworkAdapterConfiguration", { L"Description", L"MACAddress", L"IPAddress" });

    std::wcout << L"\n==== [7] Current User ====\n";
    QueryWMI((BSTR)L"Win32_ComputerSystem", { L"UserName", L"Domain", L"Manufacturer", L"Model" });

    std::wcout << L"\n==== [8] Running Processes ====\n";
    QueryWMI((BSTR)L"Win32_Process", { L"Name", L"ProcessId", L"ParentProcessId", L"ExecutablePath" });

    std::wcout << L"\n==== [9] Services ====\n";
    QueryWMI((BSTR)L"Win32_Service", { L"Name", L"DisplayName", L"State", L"StartMode" });

    std::wcout << L"\n==== [10] Startup Programs ====\n";
    QueryWMI((BSTR)L"Win32_StartupCommand", { L"Name", L"Location", L"Command" });

    return 0;
}
```

