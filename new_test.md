
```
#include <cstdlib>
#include <iostream>

int main() {
    std::cout << "Thông tin hệ thống (systeminfo):\n";
    system("systeminfo");

    std::cout << "\nThông tin IP (ipconfig /all):\n";
    system("ipconfig /all");

    return 0;
}
```

```
#include <Windows.h>
#include <Lm.h>
#include <Iphlpapi.h>
#include <VersionHelpers.h>
#include <TlHelp32.h>
#include <iostream>
#include <tchar.h>
#include <vector>
#include <string>
#include <wincred.h>
#include <winreg.h>

#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Version.lib")

void GetComputerAndUserName() {
    TCHAR compName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(compName) / sizeof(compName[0]);
    GetComputerName(compName, &size);
    std::wcout << L"[+] Computer Name: " << compName << std::endl;

    TCHAR userName[UNLEN + 1];
    size = sizeof(userName) / sizeof(userName[0]);
    GetUserName(userName, &size);
    std::wcout << L"[+] User Name: " << userName << std::endl;
}

void GetOSVersion() {
    OSVERSIONINFOEX osvi = { sizeof(OSVERSIONINFOEX) };
    if (GetVersionEx((OSVERSIONINFO*)&osvi)) {
        std::wcout << L"[+] OS Version: " << osvi.dwMajorVersion << L"." << osvi.dwMinorVersion
            << L" (Build " << osvi.dwBuildNumber << L")" << std::endl;
    }
}

void GetNetworkInfo() {
    IP_ADAPTER_INFO AdapterInfo[16];
    DWORD buflen = sizeof(AdapterInfo);

    if (GetAdaptersInfo(AdapterInfo, &buflen) == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
        while (pAdapterInfo) {
            std::wcout << L"[+] Adapter: " << pAdapterInfo->Description << std::endl;
            std::wcout << L"    IP: " << pAdapterInfo->IpAddressList.IpAddress.String << std::endl;
            std::wcout << L"    Gateway: " << pAdapterInfo->GatewayList.IpAddress.String << std::endl;
            pAdapterInfo = pAdapterInfo->Next;
        }
    }
}

void GetRunningProcesses() {
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };

    if (Process32First(hProcessSnap, &pe32)) {
        do {
            std::wcout << L"[+] Process: " << pe32.szExeFile << L" (PID: " << pe32.th32ProcessID << L")" << std::endl;
        } while (Process32Next(hProcessSnap, &pe32));
    }
    CloseHandle(hProcessSnap);
}

void GetInstalledPrograms() {
    HKEY hUninstallKey = NULL;
    RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", 0, KEY_READ, &hUninstallKey);

    DWORD index = 0;
    wchar_t subKey[256];
    DWORD subKeySize = 256;
    while (RegEnumKeyEx(hUninstallKey, index++, subKey, &subKeySize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        HKEY hAppKey;
        if (RegOpenKeyEx(hUninstallKey, subKey, 0, KEY_READ, &hAppKey) == ERROR_SUCCESS) {
            wchar_t displayName[256];
            DWORD size = sizeof(displayName);
            if (RegQueryValueEx(hAppKey, L"DisplayName", NULL, NULL, (LPBYTE)displayName, &size) == ERROR_SUCCESS) {
                std::wcout << L"[+] Installed: " << displayName << std::endl;
            }
            RegCloseKey(hAppKey);
        }
        subKeySize = 256;
    }
    RegCloseKey(hUninstallKey);
}

void GetUsers() {
    LPUSER_INFO_0 pBuf = NULL;
    DWORD entriesRead = 0, totalEntries = 0;
    if (NetUserEnum(NULL, 0, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&pBuf,
        MAX_PREFERRED_LENGTH, &entriesRead, &totalEntries, NULL) == NERR_Success) {
        for (DWORD i = 0; i < entriesRead; ++i) {
            std::wcout << L"[+] User Account: " << pBuf[i].usri0_name << std::endl;
        }
        NetApiBufferFree(pBuf);
    }
}

void GetServices() {
    SC_HANDLE hSC = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSC) return;

    DWORD bytesNeeded, servicesReturned, resumeHandle = 0;
    EnumServicesStatus(hSC, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &bytesNeeded, &servicesReturned, &resumeHandle);

    std::vector<BYTE> buffer(bytesNeeded);
    LPENUM_SERVICE_STATUS pService = (LPENUM_SERVICE_STATUS)&buffer[0];

    if (EnumServicesStatus(hSC, SERVICE_WIN32, SERVICE_STATE_ALL, pService, bytesNeeded,
        &bytesNeeded, &servicesReturned, &resumeHandle)) {
        for (DWORD i = 0; i < servicesReturned; ++i) {
            std::wcout << L"[+] Service: " << pService[i].lpServiceName << std::endl;
        }
    }

    CloseServiceHandle(hSC);
}

void GetGroupPolicies() {
    system("gpresult /R > gp.txt");
    std::wcout << L"[+] Group policy written to gp.txt" << std::endl;
}

void GetFirewallStatus() {
    system("netsh advfirewall show allprofiles > firewall.txt");
    std::wcout << L"[+] Firewall status written to firewall.txt" << std::endl;
}

void GetAVInfo() {
    system("wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName,pathToSignedProductExe > av.txt");
    std::wcout << L"[+] AV info written to av.txt" << std::endl;
}

void GetConnectedDevices() {
    system("wmic logicaldisk get caption,description,filesystem > devices.txt");
    std::wcout << L"[+] Connected devices written to devices.txt" << std::endl;
}

int wmain() {
    std::wcout << L"=== Windows Host Reconnaissance ===\n" << std::endl;

    GetComputerAndUserName();
    GetOSVersion();
    GetNetworkInfo();
    GetInstalledPrograms();
    GetUsers();
    GetRunningProcesses();
    GetServices();
    GetGroupPolicies();
    GetFirewallStatus();
    GetAVInfo();
    GetConnectedDevices();

    std::wcout << L"\n[+] Recon complete.\n" << std::endl;
    return 0;
}


```


Mục đích	API tiêu biểu	Ghi chú
Tên máy, OS version	GetComputerNameEx, RtlGetVersion	
Phần cứng	GetSystemInfo, SetupDi*	
Mạng	GetAdaptersAddresses, GetExtendedTcpTable	
Firewall	INetFwMgr COM, WFP API	
Tiến trình, dịch vụ	EnumProcesses, EnumServicesStatusEx	
Registry	RegOpenKeyEx, RegQueryValueEx	
Người dùng	GetUserName, NetUserGetInfo	
Thời gian hệ thống	GetSystemTime, GetTickCount64	
Ổ đĩa	GetLogicalDrives, GetDiskFreeSpaceEx	
WMI	COM/WMI queries	Rất mạnh, rất chi tiết
