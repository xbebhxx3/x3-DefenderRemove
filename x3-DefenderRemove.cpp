#include "x3-f.h"
using namespace std;

int main(int argc, char** argv) {
	RunAsTi(); 
	printf("x3-DefenderRemove.exe [c]\n");
	printf("Windows Defenderж�ع���  v2.0\n");
	printf("����:admin@n103.top\n");
	printf("����:www.n103.top\n");
	printf("                          by:  xbebhxx3\n\n");
	printf("�޷�ɾ����������������\n");
	printf("c\tȷ��\n");
	printf("x3-DefenderRemove.exe c\n");
	if(argc==1){
		printf("�س�����...");
		cin.sync();
		cin.get();
	}
	KillProcess("MsMpEng.exe");
	KillProcess("smartscreen.exe");
	KillProcess("SecurityHealthHost.exe");
	KillProcess("SecurityHealthSystray.exe");
	KillProcess("SecurityHealthService.exe");//�������н��� 
	
	system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f");
	system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f");
	system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableOnAccessProtection /t REG_DWORD /d 1 /f");
	system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f");
	system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableScanOnRealtimeEnable /t REG_DWORD /d 1 /f");
	system("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\SecurityHealthService\" /v Start /t REG_DWORD /d 4 /f");//ע�����ã������Ǵ����ж�wd���������(����

	if(CloseService("Sense"))printf("[-] ֹͣ����Sense(Windows Defender Advanced Threat Protection Service)ʧ��\n"); 
	else printf("[+] ֹͣ����Sense(Windows Defender Advanced Threat Protection Service)�ɹ�\n"); 
	if(CloseService("WdNisSvc"))printf("[-] ֹͣ����WdNisSvc(Windows Defender Antivirus Network Inspection Service)ʧ��\n"); 
	else printf("[+] ֹͣ����WdNisSvc(Windows Defender Antivirus Network Inspection Service)�ɹ�\n"); 
	if(CloseService("WinDefend"))printf("[-] ֹͣ����WinDefend(Windows Defender Antivirus Service)ʧ��\n"); 
	else printf("[+] ֹͣ����WinDefend(Windows Defender Antivirus Service)�ɹ�\n"); 
	if(CloseService("mpssvc"))printf("[-] ֹͣ����mpssvc(Windows Defender Firewall)ʧ��\n"); 
	else printf("[+] ֹͣ����mpssvc(Windows Defender Firewall)�ɹ�\n"); 
	if(CloseService("SecurityHealthService"))printf("[-] ֹͣ����SecurityHealthService(Windows ��ȫ���ķ���)ʧ��\n"); 
	else printf("[+] ֹͣ����SecurityHealthService(Windows ��ȫ���ķ���)�ɹ�\n"); 
	if(CloseService("WdNisDrv"))printf("[-] ֹͣ����WdNisDrv(Windows ��ȫ���ķ���)ʧ��\n"); 
	else printf("[+] ֹͣ����SecurityHealthService(Windows ��ȫ���ķ���)�ɹ�\n"); 
	if(CloseService("wscsvc"))printf("[-] ֹͣ����WSCSVC(Windows ��ȫ����)������Ӳ����������ϵİ�ȫ��������ʧ��\n"); 
	else printf("[+] ֹͣ����WSCSVC(Windows ��ȫ����)������Ӳ����������ϵİ�ȫ�������óɹ�\n"); //ֹͣ���з���
	
	if(DelReg("SYSTEM\\CurrentControlSet\\Services\\Sense"))printf("[-] ɾ������Sense(Windows Defender Advanced Threat Protection Service)ʧ��\n"); 
	else printf("[+] ɾ������Sense(Windows Defender Advanced Threat Protection Service)�ɹ�\n"); 
	if(DelReg("SYSTEM\\CurrentControlSet\\Services\\WdNisSvc"))printf("[-] ɾ������WdNisSvc(Windows Defender Antivirus Network Inspection Service)ʧ��\n"); 
	else printf("[+] ɾ������WdNisSvc(Windows Defender Antivirus Network Inspection Service)�ɹ�\n"); 
	if(DelReg("SYSTEM\\CurrentControlSet\\Services\\WinDefend"))printf("[-] ɾ������WinDefend(Windows Defender Antivirus Service)ʧ��\n"); 
	else printf("[+] ɾ������WinDefend(Windows Defender Antivirus Service)�ɹ�\n"); 
	if(DelReg("SYSTEM\\CurrentControlSet\\Services\\mpssvc"))printf("[-] ɾ������mpssvc(Windows Defender Firewall)ʧ��\n"); 
	else printf("[+] ɾ������mpssvc(Windows Defender Firewall)�ɹ�\n"); 
	if(DelReg("SYSTEM\\CurrentControlSet\\Services\\SecurityHealthService"))printf("[-] ɾ������SecurityHealthService(Windows ��ȫ���ķ���)ʧ��\n"); 
	else printf("[+] ɾ������SecurityHealthService(Windows ��ȫ���ķ���)�ɹ�\n"); 
	if(DelReg("SYSTEM\\CurrentControlSet\\Services\\wscsvc"))printf("[-] ɾ������WSCSVC(Windows ��ȫ����)������Ӳ����������ϵİ�ȫ��������ʧ��\n"); 
	else printf("[+] ɾ������WSCSVC(Windows ��ȫ����)������Ӳ����������ϵİ�ȫ�������óɹ�\n"); //ɾ�����з��� 
	
	if(DelRegValue("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run","SecurityHealth"))printf("[-] ɾ��64λ������ʧ��\n"); 
	else printf("[+] ɾ��64λ������ɹ�\n"); 
	if(DelRegValue("SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run","SecurityHealth"))printf("[-] ɾ��32λ������ʧ��\n"); 
	else printf("[+] ɾ��32λ������ɹ�\n");//ɾ�������� 
	
	if (RegDeleteKey(HKEY_CLASSES_ROOT, "*\\shellex\\ContextMenuHandlers\\EPP") == ERROR_SUCCESS)printf("[-] ɾ���Ҽ��˵�ʧ��\n"); 
	else printf("[+] ɾ���Ҽ��˵��ɹ�\n"); 
	if (RegDeleteKey(HKEY_CLASSES_ROOT, "Directory\\shellex\\ContextMenuHandlers\\EPP") == ERROR_SUCCESS)printf("[-] ɾ���Ҽ��˵�1ʧ��\n"); 
	else printf("[+] ɾɾ���Ҽ��˵�1�ɹ�\n"); //ɾ���Ҽ��˵� 
	
	system("rd /S /Q \"%SystemDrive%\\Windows\\SystemApps\\Microsoft.Windows.SecHealthUI_cw5n1h2txyewy\"");
	system("rd /S /Q \"%SystemDrive%\\ProgramData\\Microsoft\\Windows Defender\"");
	system("rd /S /Q \"%SystemDrive%\\Program Files\\Windows Defender\"");
	system("rd /S /Q \"%SystemDrive%\\Program Files (x86)\\Windows Defender\"");
	system("rd /S /Q \"%SystemDrive%\\Program Files\\Windows Defender Advanced Threat Protection\"");
	system("rd /S /Q \"%SystemDrive%\\Program Files (x86)\\Windows Defender Advanced Threat Protection\"");
	
	system("del /F /S /Q \"%SystemDrive%\\Windows\\System32\\SecurityHealthService.exe\"");
	system("del /F /S /Q \"%SystemDrive%\\Windows\\System32\\SecurityHealthSystray.exe\"");
	system("del /F /S /Q \"%SystemDrive%\\Windows\\System32\\wscsvc.dll\"");
	system("del /F /S /Q \"%SystemDrive%\\Windows\\System32\\SecurityHealthAgent.dll\"");
	system("del /F /S /Q \"%SystemDrive%\\Windows\\System32\\FirewallAPI.dll\"");
	system("del /F /S /Q \"%SystemDrive%\\Windows\\System32\\smartscreen.exe\"");//ɾ���ļ� 
	if(argc==1){
		printf("�س��˳�...");
		cin.sync();
		cin.get();
	}
	
	return 0;
}
