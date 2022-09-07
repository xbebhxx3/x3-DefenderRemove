#include "x3-f.h"
using namespace std;

int main(int argc, char** argv) {
	RunAsTi(); 
	printf("x3-DefenderRemove.exe [c]\n");
	printf("Windows Defender卸载工具  v1.0\n");
	printf("邮箱:admin@n103.top\n");
	printf("官网:www.n103.top\n");
	printf("                          by:  xbebhxx3\n\n");
	printf("无法删除请重启后再运行\n");
	printf("c\t确定\n");
	printf("x3-DefenderRemove.exe c\n");
	if(argc==1){
		printf("回车继续...");
		cin.sync();
		cin.get();
	}
	KillProcess("MsMpEng.exe");
	KillProcess("smartscreen.exe");
	KillProcess("SecurityHealthHost.exe");
	KillProcess("SecurityHealthSystray.exe");
	KillProcess("SecurityHealthService.exe");//结束所有进程 
	
	if(CloseService("Sense"))printf("[-] 停止服务Sense(Windows Defender Advanced Threat Protection Service)失败\n"); 
	else printf("[+] 停止服务Sense(Windows Defender Advanced Threat Protection Service)成功\n"); 
	if(CloseService("WdNisSvc"))printf("[-] 停止服务WdNisSvc(Windows Defender Antivirus Network Inspection Service)失败\n"); 
	else printf("[+] 停止服务WdNisSvc(Windows Defender Antivirus Network Inspection Service)成功\n"); 
	if(CloseService("WinDefend"))printf("[-] 停止服务WinDefend(Windows Defender Antivirus Service)失败\n"); 
	else printf("[+] 停止服务WinDefend(Windows Defender Antivirus Service)成功\n"); 
	if(CloseService("mpssvc"))printf("[-] 停止服务mpssvc(Windows Defender Firewall)失败\n"); 
	else printf("[+] 停止服务mpssvc(Windows Defender Firewall)成功\n"); 
	if(CloseService("SecurityHealthService"))printf("[-] 停止服务SecurityHealthService(Windows 安全中心服务)失败\n"); 
	else printf("[+] 停止服务SecurityHealthService(Windows 安全中心服务)成功\n"); 
	if(CloseService("wscsvc"))printf("[-] 停止服务WSCSVC(Windows 安全中心)服务监视并报告计算机上的安全健康设置失败\n"); 
	else printf("[+] 停止服务WSCSVC(Windows 安全中心)服务监视并报告计算机上的安全健康设置成功\n"); //停止所有服务
	
	if(DelReg("SYSTEM\\CurrentControlSet\\Services\\Sense"))printf("[-] 删除服务Sense(Windows Defender Advanced Threat Protection Service)失败\n"); 
	else printf("[+] 删除服务Sense(Windows Defender Advanced Threat Protection Service)成功\n"); 
	if(DelReg("SYSTEM\\CurrentControlSet\\Services\\WdNisSvc"))printf("[-] 删除服务WdNisSvc(Windows Defender Antivirus Network Inspection Service)失败\n"); 
	else printf("[+] 删除服务WdNisSvc(Windows Defender Antivirus Network Inspection Service)成功\n"); 
	if(DelReg("SYSTEM\\CurrentControlSet\\Services\\WinDefend"))printf("[-] 删除服务WinDefend(Windows Defender Antivirus Service)失败\n"); 
	else printf("[+] 删除服务WinDefend(Windows Defender Antivirus Service)成功\n"); 
	if(DelReg("SYSTEM\\CurrentControlSet\\Services\\mpssvc"))printf("[-] 删除服务mpssvc(Windows Defender Firewall)失败\n"); 
	else printf("[+] 删除服务mpssvc(Windows Defender Firewall)成功\n"); 
	if(DelReg("SYSTEM\\CurrentControlSet\\Services\\SecurityHealthService"))printf("[-] 删除服务SecurityHealthService(Windows 安全中心服务)失败\n"); 
	else printf("[+] 删除服务SecurityHealthService(Windows 安全中心服务)成功\n"); 
	if(DelReg("SYSTEM\\CurrentControlSet\\Services\\wscsvc"))printf("[-] 删除服务WSCSVC(Windows 安全中心)服务监视并报告计算机上的安全健康设置失败\n"); 
	else printf("[+] 删除服务WSCSVC(Windows 安全中心)服务监视并报告计算机上的安全健康设置成功\n"); //删除所有服务 
	
	if(DelRegValue("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run","SecurityHealth"))printf("[-] 删除64位启动项失败\n"); 
	else printf("[+] 删除64位启动项成功\n"); 
	if(DelRegValue("SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run","SecurityHealth"))printf("[-] 删除32位启动项失败\n"); 
	else printf("[+] 删除32位启动项成功\n");//删除启动项 
	
	if (RegDeleteKey(HKEY_CLASSES_ROOT, "*\\shellex\\ContextMenuHandlers\\EPP") == ERROR_SUCCESS)printf("[-] 删除右键菜单失败\n"); 
	else printf("[+] 删除右键菜单成功\n"); 
	if (RegDeleteKey(HKEY_CLASSES_ROOT, "Directory\\shellex\\ContextMenuHandlers\\EPP") == ERROR_SUCCESS)printf("[-] 删除右键菜单1失败\n"); 
	else printf("[+] 删删除右键菜单1成功\n"); //删除右键菜单 
	
	system("rd /S /Q \"%SystemDrive%\\Windows\\SystemApps\\Microsoft.Windows.SecHealthUI_cw5n1h2txyewy\"");
	system("rd /S /Q \"%SystemDrive%\\ProgramData\\Microsoft\\Windows Defender\"");
	system("rd /S /Q \"%SystemDrive%\\Program Files\\Windows Defender\"");
	system("rd /S /Q \"%SystemDrive%\\Program Files (x86)\\Windows Defender\"");
	system("rd /S /Q \"%SystemDrive%\\Program Files\\Windows Defender Advanced Threat Protection\"");
	system("rd /S /Q \"%SystemDrive%\\Program Files (x86)\\Windows Defender Advanced Threat Protection\"");
	
	system("del /F /S /Q \"%SystemDrive%\\Windows\\System32\\SecurityHealthService.exe\"");
	system("del /F /S /Q \"%SystemDrive%\\Windows\\System32\\SecurityHealthSystray.exe\"");
	system("del /F /S /Q \"%SystemDrive%\\Windows\\System32\\smartscreen.exe\"");//删除文件 
	if(argc==1){
		printf("回车退出...");
		cin.sync();
		cin.get();
	}
	
	return 0;
}
