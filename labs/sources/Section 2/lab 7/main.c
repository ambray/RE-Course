#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

PCHAR __declspec(dllexport) WINAPI Lab7(char* a, char* b)
{
	unsigned char* buf = NULL;
	size_t i = 0;
	size_t len_first = 0;
	size_t len_second = 0;
	size_t max_len = 0;

	if(NULL == a || NULL == b)
		return NULL;

	len_first = strlen(a);
	len_second = strlen(b);
	
	if(len_first != len_second) {
		printf("[x] Unequal!\n");
		return NULL;
	}
	max_len = len_second + 1;
	if(NULL == (buf = (unsigned char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, max_len))) {
		printf("[x]\n");
		return NULL;
	}

	for(i = 0; i < len_first; ++i)
		buf[i] = a[i] ^ b[i];

	return buf;
}


int __declspec(dllexport) WINAPI Lab7a(PLARGE_INTEGER relWait)
{
	HANDLE hTimer = NULL;

	if(NULL == relWait)
		return -1;

	if(NULL == (hTimer = CreateWaitableTimer(NULL, TRUE, NULL))) {
		printf("%d\n", GetLastError());
		return -2;
	}

	if(relWait->QuadPart > 0)
		relWait->QuadPart *= -1;

	if(!SetWaitableTimer(hTimer, relWait, 0, NULL, NULL, FALSE)) {
		printf("%d\n", GetLastError());
		CloseHandle(hTimer);
		return -3;
	}

	WaitForSingleObject(hTimer, INFINITE);
	CloseHandle(hTimer);
	return 0;
}


static int create_file(char* fname, PHANDLE io)
{
	HANDLE tmp = INVALID_HANDLE_VALUE;

	if (fname == NULL)
		return -1;

	if(INVALID_HANDLE_VALUE == (tmp = CreateFileA(fname, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 
												  NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)))
	{
		return GetLastError();
	}

	*io = tmp;
	return 0;
}

int __declspec(dllexport) WINAPI Lab7b(char* app, char* outfile)
{
	
	PROCESS_INFORMATION procInfo = {0};
	STARTUPINFO 	startInfo = {0};
	HANDLE 			hFile = INVALID_HANDLE_VALUE;
	HANDLE 			hProc = NULL;
	HANDLE 			std = NULL;
	int 			rv = 0;

	if(NULL == app || NULL == outfile)
		return -1;

	if(0 != (rv = create_file(outfile, &hFile))) {
		printf("ERROR: %d\n", rv);
		return rv;
	}

	startInfo.cb = sizeof(startInfo);
	startInfo.dwFlags |= STARTF_USESTDHANDLES;

	startInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
	startInfo.hStdOutput = hFile;
	startInfo.hStdError = hFile;

	if(!CreateProcess(NULL, app, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &startInfo, &procInfo)) {
		rv = GetLastError();
		printf("ERROR: %d\n", rv);
		goto CleanupStage1;
	}

	WaitForSingleObject(procInfo.hProcess, INFINITE);

	CloseHandle(procInfo.hProcess);
	CloseHandle(procInfo.hThread);
CleanupStage1:
	CloseHandle(hFile);
	return rv;
}


static int map_file(void** pBuf, HANDLE hFile)
{
	HANDLE 	hMap = NULL;
	void*	pMap = NULL;

	if(NULL == pBuf || INVALID_HANDLE_VALUE == hFile)
		return -1;

	if(NULL == (hMap = CreateFileMapping(hFile, NULL, PAGE_EXECUTE_READWRITE, 0, 0, NULL))) {
		printf("ERROR: %d\n", GetLastError());
		return -5;
	}

	if(NULL == (pMap = MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, 0))) {
		printf("Error with mapping! %d\n", GetLastError());
		CloseHandle(hMap);
		return -6;
	}

	CloseHandle(hMap);
	*pBuf = pMap;

	return 0;
}

int __declspec(dllexport) WINAPI Lab7f(char* fname, size_t fsize)
{
	LARGE_INTEGER 	lSize = {0};
	HANDLE 			hFile = INVALID_HANDLE_VALUE;
	HANDLE 			hMap = NULL;
	DWORD 			dwHigh = 0;
	DWORD			dwResult = 0;
	BYTE*			pByte = NULL;
	int 			rv = 0;
	DWORD			i = 0;

	if(NULL == fname || 0 == fsize)
		return -1;

	lSize.QuadPart = fsize;

	if(NULL == (hFile = CreateFileA(fname, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL))) {
		printf("ERROR: %d\n", GetLastError());
		return -2;
	}


	dwHigh = lSize.HighPart;

	if(INVALID_SET_FILE_POINTER == (dwResult = SetFilePointer(hFile, lSize.LowPart, &dwHigh, 0))) {
		printf("ERROR: %d\n", GetLastError());
		CloseHandle(hFile);
		return -3;
	}

	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, 0, NULL, 0))
		return -4;

	if(0 != (rv = map_file(&pByte, hFile))) {
		printf("ERROR: %d\n", rv);
		CloseHandle(hFile);
		return rv;
	}


	srand(GetTickCount());

	for(; i < dwResult; ++i)
		pByte[i] = rand() & 0xff;

	CloseHandle(hFile);
	UnmapViewOfFile(pByte);
	return 0;
}


int __declspec(dllexport) WINAPI Lab7c(int n)
{
	int result = 1, i = 2;
	while (i*2 < n) {
		if (n%i == 0) {
			result = 0;
			break;
		}
		i++;
	} 
	return result;
}


static void success()
{
	
	MessageBoxA(NULL, "Success!", "SUCCESS", MB_OK);
}

int __declspec(dllexport) WINAPI Lab7d(char* testVal)
{
	HANDLE 	hFile = INVALID_HANDLE_VALUE;
	char	buf[MAX_PATH+1] = {0};
	DWORD	dwBytes = 0;

	if(NULL == testVal)
		return -1;

	if(INVALID_HANDLE_VALUE == (hFile = CreateFileA("test.txt", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL))) {
		printf("File Error! %d\n", GetLastError());
		return -2;
	}

	if(!ReadFile(hFile, buf, MAX_PATH, &dwBytes, NULL) || 0 == dwBytes) {
		printf("Read Failed! %d\n", GetLastError());
		CloseHandle(hFile);
		return -3;
	}

	if(0 == strcmp(buf, testVal))
		success();

	CloseHandle(hFile);
	return 0;
}


int __declspec(dllexport) WINAPI Lab7e(char* root, size_t* outsize)
{
	DWORD sectorsPerCluster, BytesPerSector, freeClusters, clusters;

	if(NULL == root || NULL == outsize)
		return -1;

	if(!GetDiskFreeSpace(root, &sectorsPerCluster, &BytesPerSector, &freeClusters, &clusters))
		return -2;

	*outsize = sectorsPerCluster * BytesPerSector * freeClusters;
	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD dwReason, LPVOID lpRes)
{
	return TRUE;
}