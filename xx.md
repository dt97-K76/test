 
1. Clients 
Đây là những ứng dụng hoặc công cụ có thể tương tác với WMI để lấy thông tin hoặc thực hiện hành động:
•	wmic.exe: Công cụ dòng lệnh WMI.
2. Query Languages 
WQL (WMI Query Language): Ngôn ngữ truy vấn tương tự SQL dùng để lấy thông tin từ các lớp WMI.
•	CQL (Common Query Language): Chuẩn chung ít phổ biến hơn WQL.
3. WBEM Standard 
•	WBEM = Web-Based Enterprise Management – là chuẩn được WMI tuân theo.
•	Protocol Implementations:
o	DCOM: Giao thức truyền thống dùng COM để giao tiếp với WMI (nội bộ hoặc từ xa).
o	WS-Man / WinRM (Windows Remote Management): Giao thức hiện đại, thường dùng trong PowerShell Remoting.
4. WMI Providers 
Các DLL chịu trách nhiệm cung cấp thông tin cụ thể từ hệ thống:
•	cimwin32.dll: Nhà cung cấp phổ biến, cung cấp thông tin về hệ điều hành, tiến trình, dịch vụ, đĩa, v.v.
•	stdprov.dll: Nhà cung cấp chuẩn.
•	Etc.: Các nhà cung cấp khác như WMI SNMP Provider, MSI Provider, ...
5. WMI Service (Winmgmt)
•	Là dịch vụ trung tâm xử lý các yêu cầu từ client, chuyển tiếp đến các provider, trả lại dữ liệu.
•	Tên dịch vụ: Windows Management Instrumentation (winmgmt).
6. CIM Standard (Common Information Model)
•	Object Schema: Định nghĩa cấu trúc các đối tượng (WMI classes).
•	WMI Objects: Các thực thể như Win32_Process, Win32_OperatingSystem, v.v.
•	WMI/CIM Repository:
o	Là nơi lưu trữ các lớp, instance, schema.
o	Các định nghĩa lớp được quản lý bằng file MOF (Managed Object Format).
Tóm tắt dòng chảy hoạt động:
1.	Client (PowerShell, wmic, C++, ...) gửi yêu cầu truy vấn WMI (dùng WQL).
2.	Truy vấn đi qua Winmgmt (dịch vụ WMI).
3.	Winmgmt tương tác với các WMI Providers để lấy dữ liệu thực tế từ hệ thống.
4.	Dữ liệu trả về được chuẩn hóa theo CIM Schema và gửi lại cho client.

Namespaces
A namespace organizes information similar to folders in a filesystem. However, instead of physical locations (like on a disk), they are more logical in nature.

wmic /namespace:\\root path __namespace get Name
subscription
DEFAULT
CIMV2
msdtc
Cli
SECURITY
SecurityCenter2
RSOP
PEH
StandardCimv2
WMI
directory
Interop
Hardware
ServiceModel
SecurityCenter
Microsoft

CIMV2	Dữ liệu hệ thống: tiến trình, user, service, OS...	RẤT QUAN TRỌNG 🔥 – thường dùng để recon, liệt kê host, UAC, service abuse.
SECURITY	Thông tin bảo mật, audit, ACL	Dùng để kiểm tra audit policy, ẩn trace, hoặc detect hardening.
SecurityCenter / SecurityCenter2	Thông tin phần mềm bảo mật (AV, firewall)	Dùng để AV evasion, xác định phần mềm AV đang chạy.
subscription	Event Subscriptions (Event Consumers, Filters)	Persist bằng WMI Event Subscription – kỹ thuật cực mạnh, fileless, ẩn.
RSOP (Resultant Set of Policy)	Kết quả Group Policy áp dụng	Dùng để enumerate GPOs, phát hiện các ràng buộc GPO.
StandardCimv2	Thông tin hệ thống mở rộng theo chuẩn CIM	Giống như CIMV2, có thêm MSFT_ classes (PowerShell Get-CimInstance hay dùng).
PEH (Preinstallation Environment Hardware)	Cấu hình hardware (ít phổ biến)	Thường không hữu dụng cho Red Team.
Microsoft	Namespace chứa các lớp do phần mềm MS tạo	Có thể chứa thông tin ứng dụng, config, hoặc được lợi dụng cho persistence.
Cli	Dùng bởi Intel AMT hoặc phần mềm quản lý client	Có thể recon phần mềm quản lý hệ thống hoặc dấu vết điều khiển từ xa.
msdtc	Giao dịch phân tán (Microsoft Distributed Transaction Coordinator)	Ít giá trị cho Red Team trừ khi mục tiêu là MS SQL hoặc DTC abuse.
WMI	Thông tin nội bộ về chính WMI	Có thể dùng để enumerate các Event Consumer/Filter (tìm dấu vết attack hoặc ẩn persist).
Interop	Thường liên quan đến interop giữa COM/.NET	Rất hiếm khi dùng, có thể chứa lớp custom.
directory	Quản lý hệ thống file, AD (nếu domain)	Dùng trong môi trường domain để enumerate AD info.
Hardware	Thông tin phần cứng	Dùng để fingerprint máy nạn nhân, thiết bị mạng.
ServiceModel	Liên quan đến WCF (Windows Communication Foundation)	Có thể chứa endpoint nếu app dùng WCF – rare attack surface.
DEFAULT	Namespace mặc định khi không chỉ rõ	Không có lớp cụ thể, thường không hữu dụng.

	root\cimv2	Recon, liệt kê tiến trình, user, OS, services
	root\subscription	Persistence fileless qua WMI Event Subscription
	root\SecurityCenter2	AV evasion, phát hiện phần mềm AV
	root\security	Audit policy, dấu vết logs
	root\RSOP	Enumerate GPOs, ràng buộc chính sách
	root\StandardCimv2	PowerShell-friendly recon
root\Microsoft	Có thể chứa thông tin app cần recon hoặc tạo persist tùy theo cấu hình


Classes
Core classes: hey apply to all areas of management and provide few basic functionalities. You’ll usually see them starting with double underscores (e.g. __SystemSecurity).
Common classes: These are extensions of core classes, and apply to specific management areas. You’ll identify one when you see a class prefixed with CIM_ (e.g. CIM_TemperatureSensor).
Extended classes: These are extra additions to common classes based on tech stacks. (e.g. Win32_Process).

•	Abstract classes: These are templates to define new classes.
•	Static classes: Mostly used to store data.
•	Dynamic classes: These are retrieved from a provider and represents a WMI managed resource. We’re mostly interested in classes of this type.
•	Association classes: Describes relationships between classes and managed resources.
🔷 1. Abstract Classes
•	Giải thích:
Đây là những lớp trừu tượng (abstract), giống như một template (mẫu) để tạo ra các lớp khác.
•	Tính chất:
o	Không thể truy vấn trực tiếp.
o	Không chứa dữ liệu thực tế.
o	Chỉ dùng để kế thừa (inheritance).
•	Ví dụ:
CIM_LogicalDevice là một abstract class, được kế thừa bởi các class như Win32_DiskDrive, Win32_Keyboard...
•	Dùng làm gì?
Để hiểu hệ thống phân cấp (class hierarchy) hoặc viết code có tính tổng quát hơn.
________________________________________
🔷 2. Static Classes
•	Giải thích:
Là những lớp không thay đổi thường xuyên và thường chứa thông tin cấu hình hệ thống tĩnh hoặc metadata.
•	Tính chất:
o	Không bị thay đổi liên tục theo thời gian.
o	Có thể được dùng để lưu trữ thông tin hệ thống hoặc cấu hình.
•	Ví dụ:
Win32_OperatingSystem – chứa thông tin OS nhưng không thường xuyên thay đổi.
•	Dùng làm gì?
Dùng trong recon để thu thập dữ liệu hệ thống như version, arch, hostname…
________________________________________
🔷 3. Dynamic Classes
•	Giải thích:
Đây là class quan trọng nhất, cung cấp dữ liệu trực tiếp từ hệ thống thông qua provider.
•	Tính chất:
o	Thay đổi liên tục theo thời gian thực.
o	Được tạo bởi WMI provider (ví dụ: cimwin32.dll).
•	Ví dụ:
o	Win32_Process (danh sách tiến trình hiện tại).
o	Win32_Service, Win32_NetworkAdapter.
•	Dùng làm gì?
Red Team cực kỳ quan tâm – dùng để:
o	Liệt kê tiến trình.
o	Liệt kê dịch vụ, user, network, antivirus.
o	Theo dõi event (kết hợp với WMI Event Subscription).
________________________________________
🔷 4. Association Classes
•	Giải thích:
Là các class dùng để mô tả mối quan hệ giữa hai class khác trong WMI.
•	Tính chất:
o	Không chứa dữ liệu cụ thể, mà liên kết 2 lớp lại với nhau.
o	Ví dụ: "Process X được chạy bởi User Y".
•	Ví dụ:
o	Win32_LogicalDiskToPartition (liên kết ổ đĩa với phân vùng).
o	Win32_ProcessOwner (liên kết tiến trình với chủ sở hữu).
•	Dùng làm gì?
o	Tìm mối quan hệ giữa tiến trình và người dùng.
o	Truy vết kết nối giữa thiết bị - phân vùng - hệ thống file.

Get-WmiObject -Class * -List
Get-WmiObject -Class *user* -List
Get-CimClass -ClassName *user* -QualifierName dynamic

Get-CimClass -ClassName Win32_Process | Select-Object -ExpandProperty CimClassQualifiers

List method
Get-CimClass -MethodName *
Get-CimClass -MethodName Create
Get-WmiObject -Class Win32_Process -List | select -ExpandProperty Methods

Windows Registry
WMI provides a class called StdRegProv for interacting with the Windows Registry.



