Install-WindowsFeature RSAT-ADDS

Install-WindowsFeature Server-Media-Foundation

Install-WindowsFeature NET-Framework-45-Features, RPC-over-HTTP-proxy, RSAT-Clustering, RSAT-Clustering-CmdInterface, RSAT-Clustering-Mgmt, RSAT-Clustering-PowerShell, Web-Mgmt-Console, WAS-Process-Model, Web-Asp-Net45, Web-Basic-Auth, Web-Client-Auth, Web-Digest-Auth, Web-Dir-Browsing, Web-Dyn-Compression, Web-Http-Errors, Web-Http-Logging, Web-Http-Redirect, Web-Http-Tracing, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Lgcy-Mgmt-Console, Web-Metabase, Web-Mgmt-Console, Web-Mgmt-Service, Web-Net-Ext45, Web-Request-Monitor, Web-Server, Web-Stat-Compression, Web-Static-Content, Web-Windows-Auth, Web-WMI, Windows-Identity-Foundation, RSAT-ADDS

.\Setup.exe /PrepareSchema /IAcceptExchangeServerLicenseTerms_DiagnosticDataON

.\Setup.exe /IAcceptExchangeServerLicenseTerms_DiagnosticDataON /PrepareAD /OrganizationName:"LabAD"

 .\Setup.exe /IAcceptExchangeServerLicenseTerms_DiagnosticDataON /PrepareDomain:LabAD.local

 https://www.iis.net/downloads/microsoft/url-rewrite

 	Schema Admins

  	Enterprise Admins

   Domain Admins








   WMIC aliases
Wmic alias list brief
 
WMIC verbs
ASSOC
CALL
CREATE
DELETE 
GET
SET
LIST

(Get-WmiObject -List Win32_OperatingSystem).Qualifiers | ForEach-Object {
    [PSCustomObject]@{
        Name  = $_.Name
        Value = $_.Value
    }
}
WMIC switches
WMIC commands
Class
Path
context
COM API
WMI Core (CIM Object Manager)
WMI Provider

WMI Query Language (WQL):
 


Wmic 
wmic [alias | path <WMI_Class>] [where <condition>] <verb> [<property> | /format:<format>]
wmic: lệnh gọi công cụ WMIC.
alias | path <WMI_Class>:
•	alias: tên alias (bí danh) để truy vấn nhanh, ví dụ os, bios, cpu, process,...
•	path <WMI_Class>: truy vấn trực tiếp một class WMI cụ thể, ví dụ path Win32_OperatingSystem.
where <condition>: điều kiện lọc dữ liệu, ví dụ: where "Name like '%Windows%'".
<verb>: hành động bạn muốn làm, ví dụ:
•	get — lấy thuộc tính, ví dụ get Name, Version
•	list — liệt kê thông tin chi tiết
•	call — gọi một method của class
•	set — thiết lập giá trị cho một thuộc tính
•	delete — xoá instance (bản ghi)
•	create — tạo instance mới
<property>: các thuộc tính muốn lấy hoặc thao tác.
/format:<format>: định dạng xuất kết quả, ví dụ /format:list, /format:csv.

Input  WQL  COM API  WMI Provider 
1.	Managed objects and WMI providers
WMI providers consist of a DLL file and a Managed Object Format (MOF) file that defines the classes
2.	WMI infrastructure
WMI infrastructure has two components: the WMI Core, and the WMI repository.
3.	WMI consumers
 

 
Clients/Consumers
Query Languages:
Repositories
MOF files are basically used to define WMI namespaces, classes, providers, etc.
Providers
Managed Objects
Namespaces

Namespaces
A namespace organizes information similar to folders in a filesystem. However, instead of physical locations (like on a disk), they are more logical in nature.

wmic /namespace:\\root path __namespace get Name

Classes
Core classes: hey apply to all areas of management and provide few basic functionalities. You’ll usually see them starting with double underscores (e.g. __SystemSecurity).
Common classes: These are extensions of core classes, and apply to specific management areas. You’ll identify one when you see a class prefixed with CIM_ (e.g. CIM_TemperatureSensor).
Extended classes: These are extra additions to common classes based on tech stacks. (e.g. Win32_Process).

•	Abstract classes: These are templates to define new classes.
•	Static classes: Mostly used to store data.
•	Dynamic classes: These are retrieved from a provider and represents a WMI managed resource. We’re mostly interested in classes of this type.
•	Association classes: Describes relationships between classes and managed resources.
List all class with 

Get-WmiObject -Class * -List
Get-WmiObject -Class *user* -List
Get-CimClass -ClassName *user* -QualifierName dynamic

List method
Get-CimClass -MethodName *
Get-CimClass -MethodName Create
Get-WmiObject -Class Win32_Process -List | select -ExpandProperty Methods

Windows Registry
WMI provides a class called StdRegProv for interacting with the Windows Registry.

Host/OS info 
wmic computersystem get BootupState,UserName,TotalPhysicalMemory,SystemType,SystemFamily,Domain,DNSHostName

wmic os get /format:list

Directory listing 

wmic path Win32_Directory get Name
AV product 

wmic /namespace:\\root\SecurityCenter2 path AntivirusProduct get displayName /format:list

wmic service where "startname='LocalSystem'" get /format:list





 
