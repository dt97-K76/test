```
#include <windows.h>
#include <winldap.h>
#include <iostream>
#include <string>

#pragma comment(lib, "Wldap32.lib")

// Truy vấn thông tin domain/forest từ RootDSE
void GetDomainForestInfo(LDAP* ld) {
    const PWCHAR attrs[] = {
        (PWCHAR)L"defaultNamingContext",
        (PWCHAR)L"dnsHostName",
        (PWCHAR)L"domainControllerFunctionality",
        (PWCHAR)L"forestFunctionality",
        NULL
    };

    LDAPMessage* result = NULL;

    // Truy vấn RootDSE để lấy thông tin hệ thống
    ULONG err = ldap_search_sW(ld, (PWCHAR)L"", LDAP_SCOPE_BASE, (PWCHAR)L"(objectClass=*)", (PZPWSTR)attrs, 0, &result);
    if (err != LDAP_SUCCESS) {
        wprintf(L"[!] ldap_search_s failed with error code: 0x%x\n", err);
        return;
    }

    LDAPMessage* entry = ldap_first_entry(ld, result);
    if (!entry) {
        wprintf(L"[!] Không tìm thấy entry trong kết quả truy vấn.\n");
        ldap_msgfree(result);
        return;
    }

    wprintf(L"\n[+] Current Domain/Forest Information:\n");

    PWCHAR* values = nullptr;

    values = ldap_get_valuesW(ld, entry, (PWCHAR)L"defaultNamingContext");
    if (values) {
        wprintf(L"Distinguished Name: %s\n", values[0]);
        ldap_value_free(values);
    }
    else {
        wprintf(L"Distinguished Name: (null)\n");
    }

    values = ldap_get_valuesW(ld, entry, (PWCHAR)L"dnsHostName");
    if (values) {
        wprintf(L"DNS Host Name: %s\n", values[0]);
        ldap_value_free(values);
    }
    else {
        wprintf(L"DNS Host Name: (null)\n");
    }

    values = ldap_get_valuesW(ld, entry, (PWCHAR)L"domainControllerFunctionality");
    if (values) {
        wprintf(L"Domain Controller Functionality: %s\n", values[0]);
        ldap_value_free(values);
    }
    else {
        wprintf(L"Domain Controller Functionality: (null)\n");
    }

    values = ldap_get_valuesW(ld, entry, (PWCHAR)L"forestFunctionality");
    if (values) {
        wprintf(L"Forest Functionality: %s\n", values[0]);
        ldap_value_free(values);
    }
    else {
        wprintf(L"Forest Functionality: (null)\n");
    }

    ldap_msgfree(result);
}

// Function to enumerate privileged users (Domain Admins and Enterprise Admins)
void EnumeratePrivilegedUsers(LDAP* ld, const wchar_t* domainDN) {
    const wchar_t* groups[] = { L"Domain Admins", L"Enterprise Admins" };
    const wchar_t* attrs[] = { L"member", L"name", NULL };

    for (int i = 0; i < 2; i++) {
        std::wstring filter = L"(&(objectClass=group)(name=" + std::wstring(groups[i]) + L"))";
        LDAPMessage* result = NULL;
        ULONG err = ldap_search_s(ld, (PWSTR)domainDN, LDAP_SCOPE_SUBTREE, (PWSTR)filter.c_str(), (PWCHAR*)attrs, 0, &result);
        if (err != LDAP_SUCCESS) {
            wprintf(L"ldap_search_s failed for %s with error %d\n", groups[i], err);
            continue;
        }

        wprintf(L"\nMembers of %s:\n", groups[i]);
        LDAPMessage* entry = ldap_first_entry(ld, result);
        if (entry) {
            PWCHAR* members = ldap_get_values(ld, entry, (PWSTR)L"member");
            if (members) {
                for (int j = 0; members[j] != NULL; j++) {
                    wprintf(L" - %s\n", members[j]);
                }
                ldap_value_free(members);
            }
        }
        ldap_msgfree(result);
    }
}

// Function to enumerate SPN accounts (MSSQL, Exchange, RDP, etc.)
void EnumerateSPNAccounts(LDAP* ld, const wchar_t* domainDN) {
    const wchar_t* attrs[] = { L"sAMAccountName", L"servicePrincipalName", NULL };
    std::wstring filter = L"(&(objectClass=user)(servicePrincipalName=*))";
    LDAPMessage* result = NULL;
    ULONG err = ldap_search_s(ld, (PWSTR)domainDN, LDAP_SCOPE_SUBTREE, (PWSTR)filter.c_str(), (PWCHAR*)attrs, 0, &result);
    if (err != LDAP_SUCCESS) {
        wprintf(L"ldap_search_s failed with error %d\n", err);
        return;
    }

    wprintf(L"\nAccounts with SPN Set (MSSQL/Exchange/RDP/PS):\n");
    LDAPMessage* entry = ldap_first_entry(ld, result);
    while (entry) {
        PWCHAR* values = ldap_get_values(ld, entry, (PWSTR)L"sAMAccountName");
        if (values) {
            wprintf(L"Account: %s\n", values[0]);
            ldap_value_free(values);
        }
        values = ldap_get_values(ld, entry, (PWSTR)L"servicePrincipalName");
        if (values) {
            wprintf(L"SPNs:\n");
            for (int i = 0; values[i] != NULL; i++) {
                wprintf(L" - %s\n", values[i]);
            }
            ldap_value_free(values);
        }
        entry = ldap_next_entry(ld, entry);
    }
    ldap_msgfree(result);
}



int wmain(int argc, wchar_t* argv[])
{
    const wchar_t* ldapServer = NULL;  // hoặc hostname Domain Controller
    const int ldapPort = LDAP_PORT;
    const wchar_t* username = L"marry"; // dạng DOMAIN\\user
    const wchar_t* password = L"Abc123@";

    LDAP* ld = nullptr;
    ULONG version = LDAP_VERSION3;
    ULONG ret;

    // Khởi tạo kết nối
    ld = ldap_initW((PWSTR)ldapServer, ldapPort);
    if (!ld) {
        std::wcerr << L"[!] ldap_initW failed. Error: " << GetLastError() << std::endl;
        return -1;
    }
    std::wcout << L"[+] ldap_initW succeeded." << std::endl;

    // Cấu hình version
    ret = ldap_set_optionW(ld, LDAP_OPT_PROTOCOL_VERSION, (void*)&version);
    if (ret != LDAP_SUCCESS) {
        std::wcerr << L"[!] ldap_set_option failed: " << ret << std::endl;
        ldap_unbind(ld);
        return -1;
    }
    std::wcout << L"[+] Protocol version set to 3." << std::endl;

    // Kết nối
    ret = ldap_connect(ld, nullptr);
    if (ret != LDAP_SUCCESS) {
        std::wcerr << L"[!] ldap_connect failed: " << ret << std::endl;
        ldap_unbind(ld);
        return -1;
    }
    std::wcout << L"[+] ldap_connect succeeded." << std::endl;

    // Bind (xác thực)
    std::wcout << L"[~] Binding with user/pass..." << std::endl;
    ret = ldap_bind_sW(ld, (PWSTR)username, (PWSTR)password, LDAP_AUTH_SIMPLE);
    if (ret != LDAP_SUCCESS) {
        std::wcerr << L"[!] ldap_bind_sW failed: " << ret << std::endl;
        ldap_unbind(ld);
        return -1;
    }
    std::wcout << L"[+] Bind successful!" << std::endl;

    const wchar_t* domainDN = L"DC=LabAD,DC=local";

    // Gọi hàm lấy thông tin domain/forest
    GetDomainForestInfo(ld);
    EnumeratePrivilegedUsers(ld, domainDN);
    EnumerateSPNAccounts(ld, domainDN);

    // Đóng kết nối
    ldap_unbind(ld);
    return 0;
}

```


Get dc: dsquery * "dc=yourdomain,dc=local" -filter "(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" -attr distinguishedName

Get password policy: dsquery * "dc=yourdomain,dc=local" -filter "(objectClass=domainDNS)" -attr maxPwdAge minPwdLength lockoutThreshold lockoutDuration

Getuser active: dsquery * "dc=yourdomain,dc=local" -filter "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" -attr samAccountName


Get Kerberos account spn set : dsquery * "dc=yourdomain,dc=local" -filter "(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" -attr samAccountName servicePrincipalName

Get ASREPRoastable accounts (no preauth, not disabled): dsquery * "dc=yourdomain,dc=local" -filter "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!samAccountName=krbtgt))" -attr samAccountName

Get windows server : dsquery * "dc=yourdomain,dc=local" -filter "(&(objectCategory=computer)(operatingSystem=Windows Server*))" -attr name operatingSystem




List All Users: (&(objectCategory=person)(objectClass=user))

List All Enabled Users: (&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))

List All Disabled Users: (&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))

List All Computers: (objectCategory=computer)

List All Domain Admins: (&(objectCategory=person)(memberOf=CN=Domain Admins,CN=Users,DC=yourdomain,DC=com))

List All Groups: (objectCategory=group)

Find Service Principal Names (SPNs) – Kerberoasting Targets: (&(objectClass=user)(servicePrincipalName=*))

Find Machines with Unconstrained Delegation: (userAccountControl:1.2.840.113556.1.4.803:=524288)

Find Trusted Domains: (objectClass=trustedDomain)

Find GPOs (Group Policy Objects): (objectClass=groupPolicyContainer)



Get-ADObject -SearchBase "CN=Schema,CN=Configuration,DC=LabAD,DC=local" -LDAPFilter "(objectClass=classSchema)" -Properties lDAPDisplayName | 
    Select-Object lDAPDisplayName | Sort-Object lDAPDisplayName

Get-ADObject -LDAPFilter "(objectCategory=*)" -Properties objectCategory | Select-Object -ExpandProperty objectCategory | Sort-Object -Unique


LDP.exe



