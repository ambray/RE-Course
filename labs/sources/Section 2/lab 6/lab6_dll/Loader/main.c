#include <Windows.h>
#include <stdio.h>

void test_6(HMODULE hm)
{
	unsigned char buf[MAX_PATH] = { 0 };
	int status = 0;

	int (WINAPI *Lab6)(unsigned char* buf, size_t size) = NULL;

	if (NULL == (Lab6 = (int(WINAPI*)(BYTE*, size_t))GetProcAddress(hm, "_Lab6@8"))) {
		printf("Couldn't find Lab6! %d\n", GetLastError());
		return;
	}

	if (0 != (status = Lab6(buf, sizeof(buf)))) {
		printf("Lab6 Failed! %d\n", status);
	}
	else {
		printf("Lab6 Success!\n");
	}
}

void test_a(HMODULE hm)
{
	int status = 0;
	char* tmp = "alksdjfklajdfklasdjfkl;jasdklfjasdkl";
	int (WINAPI *Lab6a)(char* fname, void* contents, size_t size) = NULL;

	if (NULL == (Lab6a = (int(WINAPI*)(char*, void*, size_t))GetProcAddress(hm, "_Lab6a@12"))) {
		printf("Couldn't find Lab6a! %d\n", GetLastError());
		return;
	}


	if (0 != (status = Lab6a("tmp1.txt", tmp, strlen(tmp)))) {
		printf("Lab6a Failed! %d\n", status);
	}
	else {
		printf("Lab6a Success!\n");
	}
}

void test_b(HMODULE hm)
{
	int  status = 0;
	int (WINAPI *Lab6b)(HKEY key, char* keyPath, char* fname) = NULL;
	if (NULL == (Lab6b = (int(WINAPI*)(HKEY, char*, char*))GetProcAddress(hm, "_Lab6b@12"))) {
		printf("Couldn't find Lab6b! %d\n", GetLastError());
		return;
	}

	if (0 != (status = Lab6b(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services", "tmp2.txt"))) {
		printf("Lab6b Failed! %d\n", status);
	}
	else {
		printf("Lab6b success!\n");
	}
}

void test_c(HMODULE hm)
{
	int status = 0;
	int (WINAPI *Lab6c)(char* start, char* fname) = NULL;
	if (NULL == (Lab6c = (int(WINAPI*)(char*, char*))GetProcAddress(hm, "_Lab6c@8"))) {
		printf("Couldn't find Lab6c! %d\n", GetLastError());
		return;
	}

	if (0 != (status = Lab6c("C:\\Users\\", "tmp3.txt"))) {
		printf("Lab6c Failed! %d\n", status);
	}
	else {
		printf("Lab6c success!\n");
	}

}

void test_d(HMODULE hm)
{
	int status = 0;
	int (WINAPI *Lab6d)(UINT value) = NULL;
	if (NULL == (Lab6d = (int(WINAPI*)(UINT))GetProcAddress(hm, "_Lab6d@4"))) {
		printf("Couldn't find Lab6d! %d\n", GetLastError());
		return;
	}

	if (0 != (status = Lab6d(5))) {
		printf("Lab6d Failed! %d\n", status);
	}
	else {
		printf("Lab6d success!\n");
	}

}

int main(int argc, char** argv)
{
	HMODULE hm = NULL;

	if (NULL == (hm = LoadLibraryA("Lab6_dll.dll"))) {
		printf("Failed to load library! %d\n", GetLastError());
		return -1;
	}

	test_6(hm);
	test_a(hm);
	test_b(hm);
	test_c(hm);
	test_d(hm);

	return 0;
}