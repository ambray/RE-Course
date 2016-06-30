#include <Windows.h>


void __cdecl ExportedByName()
{
	MessageBoxA(NULL, "Hello from a function exported by name!", "EXPORT", MB_OK);
}

void __cdecl export_by_ord()
{
	MessageBoxA(NULL, "Hello from a function exported by ordinal!", "EXPORT", MB_OK);
}


BOOL WINAPI DllMain(HINSTANCE hInst, DWORD dwReason, LPVOID res)
{
	return TRUE;
}