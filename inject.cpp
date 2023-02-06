// c++ remove niger.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>


#include<tchar.h>

#include"SimpleIni.h"
#include"libmem/libmem.h"

#pragma comment(lib,"libmem.lib")

CSimpleIniA ini;


HANDLE CreateYuanShenProc() {
	auto YSPath = ini.GetValue("Inject", "GenshinPath");
	if (YSPath == nullptr) ini.GetValue("GenshinImpact", "Path");
	if (YSPath == nullptr) {
		printf("Failed to found YuanShen path\n");
		system("pause");
		exit(-1);
	}


	printf("YuanShen Path: %s\n", YSPath);

	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	if (!CreateProcessA(NULL, (char*)YSPath, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
		printf("Failed to create YuanShen process");
		exit(-2);
	}
	return pi.hProcess;
}



int
inject()
{

	ini.LoadFile("cfg.ini");

#pragma region adjustpriv
	TOKEN_PRIVILEGES priv;
	ZeroMemory(&priv, sizeof(priv));
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		priv.PrivilegeCount = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
			AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);

		CloseHandle(hToken);
	}
#pragma endregion



#pragma region opengenshin
	HANDLE hProc = CreateYuanShenProc();
	if (!hProc) {
		DWORD Err = GetLastError();
		printf("Failed to create process: 0x%X\n", Err);
		system("pause");
		return -3;
	}
	//CloseHandle(hProc);
#pragma endregion

	lm_process_t proc;

	int time = 0;
	while (!LM_FindProcess((lm_string_t)"GenshinImpact.exe", &proc)) {

		printf("can not find genshin\n");
		if (time > 10) break;
		time++;
		Sleep(1000);
	}

#pragma region injectDebugpass
	lm_module_t debugbypass;
	lm_string_t passdll = (lm_string_t)(ini.GetValue("Inject", "DebugDll", "DebuggerBypass.dll"));
	if (!LM_LoadModuleEx(&proc, passdll, &debugbypass)) {
		printf("[injectDebugpass] failed\n");
	}
#pragma endregion

#pragma region 3dmigoto

	lm_process_t proc3dm;
	lm_string_t dm = (lm_string_t)(ini.GetValue("Inject", "3dmloadername", "3DMigoto Loader.exe"));
	while (LM_FindProcess(dm, &proc3dm))
	{
		printf("wait loader close \n");
		Sleep(1000);
	}
	Sleep(5000);
#pragma endregion


#pragma region injectClibrary
	lm_string_t clib;
	lm_module_t lib;
	clib = (lm_string_t)(ini.GetValue("Inject", "CLib", "CLibrary.dll"));
	if (!LM_LoadModuleEx(&proc, clib, &lib)) {
		printf("[injectClibrary] failed");
	}
	else {
#pragma region removenigger
		printf("start remove picture\n");


		lm_process_t* pproc = &proc;
		printf("[*] Process PID:  %u\n", pproc->pid);
		printf("[*] Process PPID: %u\n", pproc->ppid);
		printf("[*] Process Name: %s\n", pproc->name);
		printf("[*] Process Path: %s\n", pproc->path);
		printf("[*] Process Bits: %zu\n", pproc->bits);
		printf("====================\n");
		lm_module_t module;
		lm_module_t* pmod = &module;
		while (!LM_FindModuleEx(pproc, (lm_string_t)"CLibrary.dll", pmod)) {
			printf("can not find CLibrary\n");
			if (time > 20) return -1;
			time++;
			Sleep(1000);
		}
		lm_address_t ptr = pmod->base + 0x395f68;
		printf("[*] Module Base: %p\n", (void*)pmod->base);
		printf("[*] Module End:  %p\n", (void*)pmod->end);
		printf("[*] Module Size: %p\n", (void*)pmod->size);
		printf("[*] Module Name: %s\n", pmod->name);
		printf("[*] Module Path: %s\n", pmod->path);
		printf("====================\n");
		printf("Sleep wait for Clibrary init\n");
		Sleep(10000);
		int value = 256;
		int tmp = 0;

		for (int i = 0; i < 20; i++) {
			if (!LM_WriteMemoryEx(pproc, (lm_address_t)ptr, (lm_bytearr_t)&value, 4)) {
				printf("写入失败\n");
			}
			Sleep(10000);
		}

#pragma endregion
	}
#pragma endregion



}
