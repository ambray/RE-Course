#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>



typedef struct BEEP_VAL_ {
	DWORD	Frequency;
	DWORD	Duration;
} BEEP_VAL, *PBEEP_VAL;

typedef struct BEEP_TASK_ {
	PBEEP_VAL	BeepList;
	size_t		ListSize;
} BEEP_TASK, *PBEEP_TASK;

typedef enum LabReturn_ {
	LabSuccess = 0,
	LabBadParam,
	LabNoMemory,
	LabOsError,
	LabNotFound,
} LabReturn;

BEEP_VAL sw[] = {
	{ 440,500 },
	{ 440,500 },
	{ 440,500 },
	{ 349,350 },
	{ 523,150 },
	{ 440,500 },
	{ 349,350 },
	{ 523,150 },
	{ 440,1000 },
	{ 659,500 },
	{ 659,500 },
	{ 659,500 },
	{ 698,350 },
	{ 523,150 },
	{ 415,500 },
	{ 349,350 },
	{ 523,150 },
	{ 523,150 },
};

BEEP_VAL harvest[] = {
	{ 329,300 },
	{ 493,300 },
	{ 698,300 },
	{ 659,600 },
	{ 783,300 },
	{ 698,300 },
	{ 659,600 },
	{ 329,100 },
	{ 493,300 },
	{ 698,300 },
	{ 659,600 },
	{ 392,250 },
	{ 440,200 },
	{ 587,300 },
	{ 349,250 },
	{ 587,500 },
	{ 329,300 },
	{ 493,300 },
	{ 698,300 },
	{ 659,600 },
	{ 783,300 },
	{ 698,300 },
	{ 659,600 },
	{ 329,100 },
	{ 493,300 },
	{ 698,300 },
	{ 659,600 },
	{ 392,250 },
	{ 440,200 },
	{ 587,300 },
	{ 349,250 },
	{ 587,400 },
};

BEEP_VAL m3[] = {
	{ 1480,200 },
	{ 1568,200 },
	{ 1568,200 },
	{ 1568,200 },
	{ 739.99,200 },
	{ 783.99,200 },
	{ 783.99,200 },
	{ 783.99,200 },
	{ 369.99,200 },
	{ 392,200 },
	{ 369.99,200 },
	{ 392,200 },
	{ 392,400 },
	{ 196,400 },
	{ 739.99,200 },
	{ 783.99,200 },
	{ 783.99,200 },
	{ 739.99,200 },
	{ 783.99,200 },
	{ 783.99,200 },
	{ 739.99,200 },
	{ 783.99,200 },
	{ 880,200 },
	{ 830.61,200 },
	{ 880,200 },
	{ 987.77,400 },
	{ 880,200 },
	{ 783.99,200 },
	{ 698.46,200 },
	{ 739.99,200 },
	{ 783.99,200 },
	{ 783.99,200 },
	{ 739.99,200 },
	{ 783.99,200 },
	{ 783.99,200 },
	{ 739.99,200 },
	{ 783.99,200 },
	{ 880,200 },
	{ 830.61,200 },
	{ 880,200 },
	{ 987.77,400 },
	{0,0}, // sleep 200
	{ 1108,10 },
	{ 1174.7,200 },
	{ 1480,10 },
	{ 1568,200 },
	{0,0}, // sleep 200
	{ 739.99,200 },
	{ 783.99,200 },
	{ 783.99,200 },
	{ 739.99,200 },
	{ 783.99,200 },
	{ 783.99,200 },
	{ 739.99,200 },
	{ 783.99,200 },
	{ 880,200 },
	{ 830.61,200 },
	{ 880,200 },
	{ 987.77,400 },
	{ 880,200 },
	{ 783.99,200 },
	{ 698.46,200 },
	{ 659.25,200 },
	{ 698.46,200 },
	{ 784,200 },
	{ 880,400 },
	{ 784,200 },
	{ 698.46,200 },
	{ 659.25,200 },
	{ 587.33,200 },
	{ 659.25,200 },
	{ 698.46,200 },
	{ 784,400 },
	{ 698.46,200 },
	{ 659.25,200 },
	{ 587.33,200 },
	{ 523.25,200 },
	{ 587.33,200 },
	{ 659.25,200 },
	{ 698.46,400 },
	{ 659.25,200 },
	{ 587.33,200 },
	{ 493.88,200 },
	{ 523.25,200 },
	{0,1},	// sleep 400
	{ 349.23,400 },
	{ 392,200 },
	{ 329.63,200 },
	{ 523.25,200 },
	{ 493.88,200 },
	{ 466.16,200 },
	{ 440,200 },
	{ 493.88,200 },
	{ 523.25,200 },
	{ 880,200 },
	{ 493.88,200 },
	{ 880,200 },
	{ 1760,200 },
	{ 440,200 },
	{ 392,200 },
	{ 440,200 },
	{ 493.88,200 },
	{ 783.99,200 },
	{ 440,200 },
	{ 783.99,200 },
	{ 1568,200 },
	{ 392,200 },
	{ 349.23,200 },
	{ 392,200 },
	{ 440,200 },
	{ 698.46,200 },
	{ 415.2,200 },
	{ 698.46,200 },
	{ 1396.92,200 },
	{ 349.23,200 },
	{ 329.63,200 },
	{ 311.13,200 },
	{ 329.63,200 },
	{ 659.25,200 },
	{ 698.46,400 },
	{ 783.99,400 },
	{ 440,200 },
	{ 493.88,200 },
	{ 523.25,200 },
	{ 880,200 },
	{ 493.88,200 },
	{ 880,200 },
	{ 1760,200 },
	{ 440,200 },
	{ 392,200 },
	{ 440,200 },
	{ 493.88,200 },
	{ 783.99,200 },
	{ 440,200 },
	{ 783.99,200 },
	{ 1568,200 },
	{ 392,200 },
	{ 349.23,200 },
	{ 392,200 },
	{ 440,200 },
	{ 698.46,200 },
	{ 659.25,200 },
	{ 698.46,200 },
	{ 739.99,200 },
	{ 783.99,200 },
	{ 392,200 },
	{ 392,200 },
	{ 392,200 },
	{ 392,200 },
	{ 196,200 },
	{ 196,200 },
	{ 196,200 },
	{ 185,200 },
	{ 196,200 },
	{ 185,200 },
	{ 196,200 },
	{ 207.65,200 },
	{ 220,200 },
	{ 233.08,200 },
	{ 246.94,200 },
};

static void WINAPI logger(char* message, DWORD code, BOOL system)
{
	char buf[MAX_PATH + 1] = { 0 };
	char* fmt = (code == 0) ? "[DEBUG] %s : %d : %s\n" : "[DEBUG][X] ERROR: %s : %d : %s";
	char* msg = NULL;

	if (NULL == message)
		return;

	if (system) {
		FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER, NULL, code, 0, msg, 0, NULL);
	}
	else {
		msg = "    ";
	}

	_snprintf(buf, MAX_PATH, fmt, message, code, msg);

	OutputDebugStringA(buf);

	if (system && NULL != msg)
		HeapFree(GetProcessHeap(), 0, msg);
}

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD dwReason, LPVOID lpRes)
{
	return TRUE;
}


LabReturn __declspec(dllexport) WINAPI Lab6(unsigned char* buf, size_t size)
{
	size_t i = 0;

	srand(GetTickCount());

	if (NULL == buf || 0 == size)
		return LabBadParam;

	for (; i < size; ++i)
		buf[i] = rand() & 0xff;
	
	return LabSuccess;
}


LabReturn __declspec(dllexport) WINAPI Lab6a(char* fname, void* contents, size_t size)
{
	HANDLE		hFile = INVALID_HANDLE_VALUE;
	DWORD		dwBytes = 0;
	LabReturn	rv = LabSuccess;

	if (NULL == fname || (NULL == contents && 0 != size)) {
		logger("Bad Value provided for method!", LabBadParam, FALSE);
		rv = LabBadParam;
		goto End;
	}

	if (INVALID_HANDLE_VALUE == (hFile = CreateFileA(fname, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL))) {
		logger("Failed to open!", GetLastError(), TRUE);
		rv = LabOsError;
		goto End;
	}

	if (!WriteFile(hFile, contents, size, &dwBytes, NULL) || 0 == dwBytes) {
		logger("Failed to write!", GetLastError(), TRUE);
		goto Cleanup;
	}

	logger("Success!", 0, TRUE);
Cleanup:
	CloseHandle(hFile);
End:
	return rv;
}


static LabReturn printKeys(HKEY initial, FILE* fp)
{
	LabReturn	rv = LabSuccess;
	FILETIME	ftLastWrite = { 0 };
	SYSTEMTIME	sysTime = { 0 };
	HKEY		hCurrent = NULL;
	DWORD		dwSize = MAX_PATH;
	char		buf[MAX_PATH + 1] = { 0 };
	int			status = ERROR_SUCCESS;
	int			i = 0;

	if (NULL == initial || NULL == fp) {
		logger("Bad Parameters!", ERROR_INVALID_PARAMETER, TRUE);
		rv = LabBadParam;
		goto Done;
	}


	while (ERROR_SUCCESS == (status = RegEnumKeyExA(initial, i, buf, &dwSize, NULL, NULL, NULL, &ftLastWrite))) {
		if (!FileTimeToSystemTime(&ftLastWrite, &sysTime)) {
			logger("File time conversion failed!", GetLastError(), TRUE);
			continue;
		}

		fprintf(fp, "-> Key: %s | [Last Modified: %hu/%hu/%hu : %hu:%hu:%hu ]\n", buf, sysTime.wMonth, sysTime.wDay, sysTime.wYear,
			    sysTime.wHour, sysTime.wMinute, sysTime.wSecond);

		memset(buf, 0, sizeof(buf));
		++i;
		dwSize = MAX_PATH;
	}

Done:
	return rv;
}

LabReturn __declspec(dllexport) WINAPI Lab6b(HKEY key, char* keyPath, char* fname)
{
	HKEY		hKey = NULL;
	LSTATUS		status = 0;
	FILE*		fp = NULL;
	LabReturn	rv = LabSuccess;

	if (NULL == keyPath || NULL == fname) {
		logger("Bad value provided!", LabBadParam, FALSE);
		return LabBadParam;
	}

	if(ERROR_SUCCESS != (status = RegOpenKeyExA(key, keyPath, 0, KEY_ENUMERATE_SUB_KEYS, &hKey))) {
		logger("Something went wrong opening key!", status, TRUE);
		return LabOsError;
	}

	if (NULL == (fp = fopen(fname, "w"))) {
		logger("Unable to open output file!", GetLastError(), TRUE);
		rv = LabOsError;
		goto Cleanup;
	}

	rv = printKeys(hKey, fp);

	fclose(fp);
Cleanup:
	RegCloseKey(hKey);
	return LabSuccess;
}

static int read_files(char* root, UINT depth, FILE* hLog)
{
	char buf[MAX_PATH + 4] = { 0 };
	BOOL isDir = FALSE;
	WIN32_FIND_DATA data = { 0 };
	HANDLE hFound = INVALID_HANDLE_VALUE;
	char* fmtFileReg = "-> %s\n";
	char* fmtFileDir = "[%s]\n";

	if (NULL == root || NULL == hLog)
		return ERROR_INVALID_PARAMETER;

	if (0 == depth)
		return ERROR_NO_MORE_FILES;

	_snprintf(buf, MAX_PATH, "%s\\*.*", root);
	if (INVALID_HANDLE_VALUE == (hFound = FindFirstFileA(buf, &data))) {
		return GetLastError();
	}

	do {
		isDir = data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY;

		if (strcmp(".", data.cFileName) && strcmp("..", data.cFileName)) {
			fprintf(hLog, (isDir ? fmtFileDir : fmtFileReg), data.cFileName);
		}

		if (isDir && '.' != *(data.cFileName)) {
			ZeroMemory(buf, MAX_PATH);
			_snprintf(buf, MAX_PATH, "%s\\%s", root, data.cFileName);
			read_files(buf, depth - 1, hLog);
		}
	} while (FindNextFileA(hFound, &data));

	FindClose(hFound);
	return 0;
}


LabReturn __declspec(dllexport) WINAPI Lab6c(char* start, char* fname)
{
	FILE*		out = NULL;
	LabReturn	rv = LabSuccess;
	int			status = 0;

	if (NULL == start || NULL == fname) {
		logger("Invalid params!", ERROR_INVALID_PARAMETER, TRUE);
		return LabBadParam;
	}

	if (NULL == (out = fopen(fname, "w"))) {
		logger("Error opening file!", GetLastError(), TRUE);
		rv = LabOsError;
		return rv;
	}

	if (ERROR_SUCCESS != (status = read_files(start, 5, out))) {
		logger("Something bad happened!", status, TRUE);
		rv = LabOsError;
		goto Cleanup;
	}

	logger("Done.", 0, FALSE);

Cleanup:
	fclose(out);
	return LabSuccess;
}

static DWORD WINAPI m3_func(PBEEP_TASK task)
{
	int i = 0;

	if (NULL == task)
		return (DWORD)-1;

	for (i = 0; i < task->ListSize; ++i) {
		if (task->BeepList[i].Frequency == 0) {
			Sleep((task->BeepList[i].Duration == 0) ? 200 : 400);
		} 

		Beep(m3[i].Frequency, m3[i].Duration);
	}

	return 0;
}

LabReturn __declspec(dllexport) WINAPI Lab6d(UINT value)
{
	HANDLE		hThread = NULL;
	PBEEP_TASK	pTask = NULL;


	if (NULL == (pTask = (PBEEP_TASK)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*pTask)))) {
		logger("Out of memory!", ERROR_OUTOFMEMORY, TRUE);
		return LabNoMemory;
	}

	switch (value) {
	case 0:
	case 1:
	case 2:
		MessageBox(NULL, "This is not the value you are looking for, but almost!", "NOT QUITE!", MB_ICONERROR);
		break;
	case 5:
		pTask->BeepList = m3;
		pTask->ListSize = sizeof(m3) / sizeof(BEEP_VAL);
		if (NULL == (hThread = CreateThread(NULL, 0, m3_func, pTask, 0, NULL))) {
			logger("Thread creation failed!", GetLastError(), TRUE);
			break;
		}
		WaitForSingleObject(hThread, INFINITE);
		break;
	case 6:
		pTask->BeepList = harvest;
		pTask->ListSize = sizeof(harvest) / sizeof(BEEP_VAL);
		if (NULL == (hThread = CreateThread(NULL, 0, m3_func, pTask, 0, NULL))) {
			logger("Thread creation failed!", GetLastError(), TRUE);
			break;
		}
		WaitForSingleObject(hThread, INFINITE);
		break;
	case 7:
		pTask->BeepList = sw;
		pTask->ListSize = sizeof(sw) / sizeof(BEEP_VAL);
		if (NULL == (hThread = CreateThread(NULL, 0, m3_func, pTask, 0, NULL))) {
			logger("Thread creation failed!", GetLastError(), TRUE);
			break;
		}
		WaitForSingleObject(hThread, INFINITE);
		break;
	default:
		logger("Invalid input provided!", LabBadParam, FALSE);
	}

	if (NULL != hThread)
		CloseHandle(hThread);
	HeapFree(GetProcessHeap(), 0, pTask);
	return LabSuccess;
}