#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <Wtsapi32.h>
#include <stdio.h>


void __declspec(dllexport) Lab3a()
{
	PWTS_PROCESS_INFO	pInfo = NULL;
	DWORD				pCount = 0;
	DWORD				bytes = 0;
	int					i = 0;

	if (!WTSEnumerateProcessesA(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pInfo, &pCount)) {
		printf("[x] Operation failed! %lu\n", GetLastError());
		return;
	}

	for (i = 0; i < pCount; ++i) {
		printf("%lu : %s\n", pInfo[i].ProcessId, pInfo[i].pProcessName);
	}

	WTSFreeMemory(pInfo);

}

int main(int argc, char** argv)
{
	Lab3a();
	return 0;
}