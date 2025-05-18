```
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>
#include <lm.h>
#include <sddl.h>
#include <tchar.h>
#include <iostream>
#include <string>
#include <vector>
#include <dsrole.h>
#include <map>
#include <winnetwk.h>
#include <sstream>
#include <io.h>
#include <fcntl.h>
#include <netfw.h>
#include <wscapi.h>


#pragma comment(lib, "wscapi.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Mpr.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")


typedef LONG(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

void PrintComputerInfo() {
    WCHAR name[256];
    DWORD size = sizeof(name) / sizeof(WCHAR);
    if (GetComputerNameW(name, &size)) {
        std::wcout << L"[+] Computer Name: " << name << std::endl;
    }
    else {
        std::wcerr << L"[-] Failed to get computer name.\n";
    }

    RTL_OSVERSIONINFOW rovi = { 0 };
    rovi.dwOSVersionInfoSize = sizeof(rovi);

    HMODULE hMod = GetModuleHandleW(L"ntdll.dll");
    if (hMod) {
        RtlGetVersionPtr fnRtlGetVersion = (RtlGetVersionPtr)GetProcAddress(hMod, "RtlGetVersion");
        if (fnRtlGetVersion) {
            if (fnRtlGetVersion(&rovi) == 0) {
                std::wcout << L"[+] Windows version: "
                    << rovi.dwMajorVersion << L"."
                    << rovi.dwMinorVersion << L" Build "
                    << rovi.dwBuildNumber << std::endl;
            }
            else {
                std::wcerr << L"[-] RtlGetVersion failed.\n";
            }
        }
        else {
            std::wcerr << L"[-] Can't find RtlGetVersion.\n";
        }
    }
    else {
        std::wcerr << L"[-] Can't get ntdll.dll module.\n";
    }

    SYSTEM_INFO si = { 0 };
    GetNativeSystemInfo(&si);
    std::wcout << L"[+] Architecture: "
        << ((si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) ? L"x64" :
            (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) ? L"ARM64" :
            (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) ? L"x86" :
            L"Unknown") << std::endl;

    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(memInfo);

    if (GlobalMemoryStatusEx(&memInfo)) {
        DWORDLONG totalPhys = memInfo.ullTotalPhys / (1024 * 1024);   // Tổng RAM vật lý (MB)
        DWORDLONG availPhys = memInfo.ullAvailPhys / (1024 * 1024);   // RAM còn trống (MB)
        DWORDLONG usedPhys = totalPhys - availPhys;

        std::wcout << L"[+] Total Physical RAM: " << totalPhys << L" MB\n";
        std::wcout << L"[+] Used  Physical RAM: " << usedPhys << L" MB\n";
        std::wcout << L"[+] Free  Physical RAM: " << availPhys << L" MB\n";
    }
    else {
        std::wcerr << L"[-] Failed to get memory status.\n";
    }

    ULONGLONG uptime = GetTickCount64() / 1000;
    std::wcout << L"[+] Uptime: " << uptime << L" seconds" << std::endl;

    WCHAR sdir[256];
    DWORD sizesdir = sizeof(sdir) / sizeof(WCHAR);
    if (GetSystemDirectoryW(sdir, sizesdir)) {
        std::wcout << L"[+] System directory: " << sdir << std::endl;
    }
    else {
        std::wcerr << L"[-] Can't get system directory.\n";
    }

    if (GetWindowsDirectoryW(sdir, sizesdir)) {
        std::wcout << L"[+] Windows directory: " << sdir << std::endl;
    }
    else {
        std::wcerr << L"[-] Can't get windows directory.\n";
    }

    SYSTEMTIME stUTC, stLocal;
    GetSystemTime(&stUTC);
    GetLocalTime(&stLocal);

    wprintf(L"[UTC  ] %02d:%02d:%02d\n", stUTC.wHour, stUTC.wMinute, stUTC.wSecond);
    wprintf(L"[Local] %02d:%02d:%02d\n", stLocal.wHour, stLocal.wMinute, stLocal.wSecond);
}

void PrintUserInfo() {
    // In ra tên người dùng hiện tại
    TCHAR username[256];
    DWORD size = sizeof(username) / sizeof(TCHAR);
    if (GetUserName(username, &size)) {
        std::wcout << L"[+] Username: " << username << std::endl;
    }
    else {
        std::wcerr << L"[-] Failed to get username.\n";
    }

    // Lấy SID và quyền từ token
    HANDLE hToken = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        // Lấy SID
        DWORD dwSize = 0;
        GetTokenInformation(hToken, TokenUser, nullptr, 0, &dwSize);
        PTOKEN_USER pUser = (PTOKEN_USER)malloc(dwSize);
        if (GetTokenInformation(hToken, TokenUser, pUser, dwSize, &dwSize)) {
            LPWSTR stringSid = nullptr;
            if (ConvertSidToStringSidW(pUser->User.Sid, &stringSid)) {
                std::wcout << L"[+] User SID: " << stringSid << std::endl;
                LocalFree(stringSid);
            }
        }
        free(pUser);

        // Lấy quyền (privileges)
        GetTokenInformation(hToken, TokenPrivileges, nullptr, 0, &dwSize);
        PTOKEN_PRIVILEGES pPrivs = (PTOKEN_PRIVILEGES)malloc(dwSize);
        if (GetTokenInformation(hToken, TokenPrivileges, pPrivs, dwSize, &dwSize)) {
            std::wcout << L"[+] Privileges:\n";
            for (DWORD i = 0; i < pPrivs->PrivilegeCount; ++i) {
                LUID_AND_ATTRIBUTES laa = pPrivs->Privileges[i];
                WCHAR privName[256];
                DWORD nameSize = sizeof(privName) / sizeof(WCHAR);
                if (LookupPrivilegeName(nullptr, &laa.Luid, privName, &nameSize)) {
                    std::wcout << L"    - " << privName;
                    if (laa.Attributes & SE_PRIVILEGE_ENABLED)
                        std::wcout << L" (Enabled)";
                    std::wcout << std::endl;
                }
            }
        }
        free(pPrivs);
        CloseHandle(hToken);
    }
    else {
        std::wcerr << L"[-] Failed to open process token.\n";
    }

    // Liệt kê user nội bộ
    LPUSER_INFO_0 pBuf = NULL;
    DWORD entriesRead = 0, totalEntries = 0;
    if (NetUserEnum(NULL, 0, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&pBuf,
        MAX_PREFERRED_LENGTH, &entriesRead, &totalEntries, NULL) == NERR_Success) {
        std::wcout << L"[+] Local Users:" << std::endl;
        for (DWORD i = 0; i < entriesRead; i++) {
            std::wcout << L"    - " << pBuf[i].usri0_name << std::endl;
        }
        NetApiBufferFree(pBuf);
    }
    else {
        std::wcerr << L"[-] Failed to enumerate users.\n";
    }

    // Trạng thái máy: domain hay workgroup
    LPWSTR pszName = nullptr;
    NETSETUP_JOIN_STATUS status;

    if (NetGetJoinInformation(nullptr, &pszName, &status) == NERR_Success) {
        switch (status) {
        case NetSetupUnknownStatus:
            std::wcout << L"[-] Join status: Unknown\n"; break;
        case NetSetupUnjoined:
            std::wcout << L"[-] Machine is not joined to a domain or workgroup\n"; break;
        case NetSetupWorkgroupName:
            std::wcout << L"[-] Machine is joined to a workgroup: " << pszName << L"\n"; break;
        case NetSetupDomainName:
            std::wcout << L"[+] Machine is joined to domain: " << pszName << L"\n"; break;
        default:
            std::wcout << L"[-] Join status: Unknown enum\n"; break;
        }

        if (pszName) {
            NetApiBufferFree(pszName);
        }
    }
    else {
        std::wcerr << L"[-] Failed to get join information\n";
    }

    // Kiểm tra vai trò domain (Domain Controller, Standalone, Member,...)
    PDSROLE_PRIMARY_DOMAIN_INFO_BASIC pInfo = nullptr;
    if (DsRoleGetPrimaryDomainInformation(nullptr, DsRolePrimaryDomainInfoBasic, (PBYTE*)&pInfo) == ERROR_SUCCESS) {
        switch (pInfo->MachineRole) {
        case DsRole_RoleStandaloneWorkstation:
        case DsRole_RoleStandaloneServer:
            std::wcout << L"[-] Machine is standalone workstation or server\n"; break;
        case DsRole_RoleMemberWorkstation:
        case DsRole_RoleMemberServer:
            std::wcout << L"[+] Machine is member of domain: " << pInfo->DomainNameFlat << L"\n"; break;
        case DsRole_RoleBackupDomainController:
            std::wcout << L"[!] Machine is a backup Domain Controller\n"; break;
        case DsRole_RolePrimaryDomainController:
            std::wcout << L"[!] Machine is the Primary Domain Controller (PDC) - Jackpot!\n"; break;
        default:
            std::wcout << L"[-] Unknown machine role\n"; break;
        }

        DsRoleFreeMemory(pInfo);
    }
    else {
        std::wcerr << L"[-] Failed to get domain role information\n";
    }
}

void PrintNetworkInfo() {
    std::map<std::string, std::string> dhcpMap;
    ULONG infoSize = 0;
    GetAdaptersInfo(nullptr, &infoSize);
    std::vector<BYTE> infoBuf(infoSize);
    IP_ADAPTER_INFO* pAdapterInfo = reinterpret_cast<IP_ADAPTER_INFO*>(infoBuf.data());

    if (GetAdaptersInfo(pAdapterInfo, &infoSize) == NO_ERROR) {
        for (IP_ADAPTER_INFO* p = pAdapterInfo; p; p = p->Next) {
            if (p->DhcpEnabled) {
                dhcpMap[p->AdapterName] = p->DhcpServer.IpAddress.String;
            }
        }
    }

    ULONG bufLen = 0;
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST, nullptr, nullptr, &bufLen);
    std::vector<BYTE> buf(bufLen);
    PIP_ADAPTER_ADDRESSES pAddresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());

    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST, nullptr, pAddresses, &bufLen) == NO_ERROR) {
        for (PIP_ADAPTER_ADDRESSES pCurr = pAddresses; pCurr; pCurr = pCurr->Next) {
            std::wcout << L"[+] Adapter: " << (pCurr->FriendlyName ? pCurr->FriendlyName : L"<unknown>") << std::endl;
            std::wcout << L"    - Description: " << (pCurr->Description ? pCurr->Description : L"<unknown>") << std::endl;

            if (pCurr->PhysicalAddressLength > 0) {
                wprintf(L"    - MAC: ");
                for (ULONG i = 0; i < pCurr->PhysicalAddressLength; i++) {
                    wprintf(L"%02X%s", pCurr->PhysicalAddress[i], (i == pCurr->PhysicalAddressLength - 1) ? L"" : L":");
                }
                wprintf(L"\n");
            }

            for (PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurr->FirstUnicastAddress; pUnicast; pUnicast = pUnicast->Next) {
                char ipstr[INET6_ADDRSTRLEN] = { 0 };
                int family = pUnicast->Address.lpSockaddr->sa_family;
                if (family == AF_INET) {
                    sockaddr_in* sa_in = reinterpret_cast<sockaddr_in*>(pUnicast->Address.lpSockaddr);
                    inet_ntop(AF_INET, &(sa_in->sin_addr), ipstr, sizeof(ipstr));
                    std::wcout << L"    - IPv4: " << ipstr << std::endl;
                }
                else if (family == AF_INET6) {
                    sockaddr_in6* sa_in6 = reinterpret_cast<sockaddr_in6*>(pUnicast->Address.lpSockaddr);
                    inet_ntop(AF_INET6, &(sa_in6->sin6_addr), ipstr, sizeof(ipstr));
                    std::wcout << L"    - IPv6: " << ipstr << std::endl;
                }
            }

            auto it = dhcpMap.find(std::string(pCurr->AdapterName ? pCurr->AdapterName : ""));
            if (it != dhcpMap.end()) {
                std::wcout << L"    - DHCP Server: " << std::wstring(it->second.begin(), it->second.end()) << std::endl;
            }
            std::wcout << std::endl;
        }
    }
    else {
        std::wcerr << L"[-] Failed to get adapter addresses\n";
    }
}


void PrintDrivesWithSMB() {
    DWORD drives = GetLogicalDrives();
    if (drives == 0) {
        std::wcerr << L"[-] Failed to get logical drives.\n";
        return;
    }

    std::wcout << L"[+] Logical Drives:\n";

    for (char letter = 'A'; letter <= 'Z'; ++letter) {
        if (drives & (1 << (letter - 'A'))) {
            std::wstring root = std::wstring(1, letter) + L":\\";
            std::wcout << L"    - " << root;
            UINT type = GetDriveTypeW(root.c_str());

            switch (type) {
            case DRIVE_FIXED:
                std::wcout << L" (Fixed Drive)";
                break;
            case DRIVE_REMOVABLE:
                std::wcout << L" (Removable Drive)";
                break;
            case DRIVE_CDROM:
                std::wcout << L" (CD-ROM)";
                break;
            case DRIVE_REMOTE:
                std::wcout << L" (Network/SMB Share)";

                {
                    wchar_t remoteName[MAX_PATH] = { 0 };
                    DWORD size = MAX_PATH;
                    std::wstring driveLetter = std::wstring(1, letter) + L":";
                    DWORD result = WNetGetConnectionW(driveLetter.c_str(), remoteName, &size);

                    if (result == NO_ERROR) {
                        std::wcout << L" -> UNC Path: " << remoteName;
                    }
                    else {
                        std::wcout << L" -> Failed to get UNC path (Error code: " << result << L")";
                    }
                }
                break;
            case DRIVE_NO_ROOT_DIR:
                std::wcout << L" (No Root Directory)";
                break;
            case DRIVE_RAMDISK:
                std::wcout << L" (RAM Disk)";
                break;
            case DRIVE_UNKNOWN:
            default:
                std::wcout << L" (Unknown Type)";
                break;
            }

            std::wcout << std::endl;
        }
    }
}


void QueryUninstallKey(HKEY hRootKey, const std::wstring& subKey) {
    HKEY hKey;
    LONG result = RegOpenKeyExW(hRootKey, subKey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &hKey);
    if (result != ERROR_SUCCESS) {
        std::wcerr << L"Không thể mở key registry: " << subKey << std::endl;
        return;
    }

    DWORD index = 0;
    WCHAR subKeyName[256];
    DWORD subKeyNameSize = 256;

    while (RegEnumKeyExW(hKey, index, subKeyName, &subKeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        HKEY hAppKey;
        std::wstring fullPath = subKey + L"\\" + subKeyName;

        if (RegOpenKeyExW(hRootKey, fullPath.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &hAppKey) == ERROR_SUCCESS) {
            WCHAR displayName[512];
            WCHAR displayVersion[128];
            DWORD nameSize = sizeof(displayName);
            DWORD versionSize = sizeof(displayVersion);
            DWORD type;

            if (RegQueryValueExW(hAppKey, L"DisplayName", NULL, &type, (LPBYTE)displayName, &nameSize) == ERROR_SUCCESS && type == REG_SZ) {
                std::wcout << L"- " << displayName;

                if (RegQueryValueExW(hAppKey, L"DisplayVersion", NULL, &type, (LPBYTE)displayVersion, &versionSize) == ERROR_SUCCESS && type == REG_SZ) {
                    std::wcout << L" (Version: " << displayVersion << L")";
                }

                std::wcout << std::endl;
            }

            RegCloseKey(hAppKey);
        }

        index++;
        subKeyNameSize = 256;
    }

    RegCloseKey(hKey);
}

void PrintProcessInfo() {
    std::wcout << L"[+] Running Processes:" << std::endl;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(hSnapshot, &pe)) {
        do {
            std::wcout << L"    - " << pe.szExeFile << L" (PID: " << pe.th32ProcessID << L")" << std::endl;
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
}


void PrintPathandAutoRun() {
    HKEY hKey;
    std::wcout << L"[+] Autorun Registry Keys:" << std::endl;
    if (RegOpenKeyEx(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        TCHAR name[256], value[1024];
        DWORD nameSize, valueSize, type, index = 0;
        while (true) {
            nameSize = 256;
            valueSize = 1024;
            if (RegEnumValue(hKey, index++, name, &nameSize, NULL, &type, (LPBYTE)value, &valueSize) != ERROR_SUCCESS) break;
            std::wcout << L"    - " << name << L" => " << value << std::endl;
        }
        RegCloseKey(hKey);
    }


    DWORD size = ExpandEnvironmentStringsW(L"%PATH%", nullptr, 0);
    if (size == 0)
    {
        std::wcerr << L"Failed to get buffer size for %PATH%" << std::endl;
    }

    std::wstring pathStr(size, L'\0');
    DWORD ret = ExpandEnvironmentStringsW(L"%PATH%", &pathStr[0], size);
    if (ret == 0 || ret > size)
    {
        std::wcerr << L"Failed to expand %PATH%" << std::endl;
    }

    // Resize để loại bỏ ký tự null ở cuối
    pathStr.resize(ret - 1);

    // Tách path theo dấu ';'
    std::wstringstream wss(pathStr);
    std::wstring segment;

    std::wcout << L"\nPATH environment variable paths:" << std::endl;
    while (std::getline(wss, segment, L';'))
    {
        if (!segment.empty())
        {
            std::wcout << L" - " << segment << std::endl;
        }
    }

}

void PrintFirewallProfileDetails(NET_FW_PROFILE_TYPE2 profileType, const wchar_t* profileName) {
    HRESULT hr;
    INetFwPolicy2* pNetFwPolicy2 = nullptr;
    VARIANT_BOOL enabled;
    NET_FW_ACTION action;

    hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), (void**)&pNetFwPolicy2);
    if (FAILED(hr)) {
        std::wcerr << L"[-] Failed to create INetFwPolicy2 instance.\n";
        return;
    }

    hr = pNetFwPolicy2->get_FirewallEnabled(profileType, &enabled);
    std::wcout << L"\n=== Profile: " << profileName << L" ===\n";
    std::wcout << L"    - Firewall Enabled: " << (enabled == VARIANT_TRUE ? L"Yes" : L"No") << std::endl;

    hr = pNetFwPolicy2->get_DefaultInboundAction(profileType, &action);
    std::wcout << L"    - Default Inbound Action: " << (action == NET_FW_ACTION_BLOCK ? L"Block" : L"Allow") << std::endl;

    hr = pNetFwPolicy2->get_DefaultOutboundAction(profileType, &action);
    std::wcout << L"    - Default Outbound Action: " << (action == NET_FW_ACTION_BLOCK ? L"Block" : L"Allow") << std::endl;

    VARIANT_BOOL notify;
    hr = pNetFwPolicy2->get_NotificationsDisabled(profileType, &notify);
    std::wcout << L"    - Notifications: " << (notify == VARIANT_TRUE ? L"Disabled" : L"Enabled") << std::endl;

    VARIANT_BOOL unicast;
    hr = pNetFwPolicy2->get_UnicastResponsesToMulticastBroadcastDisabled(profileType, &unicast);
    std::wcout << L"    - Unicast Responses to Broadcast: " << (unicast == VARIANT_TRUE ? L"Disabled" : L"Enabled") << std::endl;

    pNetFwPolicy2->Release();
}

void CheckFirewallStatusDetailed() {
    HRESULT hr = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        std::wcerr << L"[-] CoInitializeEx failed.\n";
        return;
    }

    std::wcout << L"[+] Windows Firewall Detailed Configuration:\n";

    PrintFirewallProfileDetails(NET_FW_PROFILE2_DOMAIN, L"Domain");
    PrintFirewallProfileDetails(NET_FW_PROFILE2_PRIVATE, L"Private");
    PrintFirewallProfileDetails(NET_FW_PROFILE2_PUBLIC, L"Public");

    CoUninitialize();
}



int main() {
    setlocale(LC_ALL, "");
    _setmode(_fileno(stdout), _O_U16TEXT);

    std::wcout << L"==== SYSTEM INFORMATION ====\n\n";

    PrintComputerInfo();

    std::wcout << L"\n==== USER INFORMATION ====\n\n";
    PrintUserInfo();

    std::wcout << L"\n==== NETWORK INFORMATION ====\n\n";
    PrintNetworkInfo();

    std::wcout << L"\n==== Drives INFORMATION ====\n\n";
    PrintDrivesWithSMB();

    std::wcout << L"[+] Installed Software List (64-bit):\n";
    QueryUninstallKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall");

    std::wcout << L"\n[+] Installed Software List (32-bit):\n";
    QueryUninstallKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall");

    std::wcout << L"\n==== PROCESS RUNNING ====\n\n";
    PrintProcessInfo();

    std::wcout << L"\n==== PATH ENVIRONMENT AND AUTORUN PROGRAMS ====\n\n";
    PrintPathandAutoRun();

    CheckFirewallStatusDetailed();
    std::wcout << L"----------------------\n";
    
    return 0;
}

```
