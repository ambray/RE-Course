#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OUTPATH             "logfile.log"
#define DIRLIST_SUCCESS     0x00
#define DIRLIST_NOMEMORY    0x01
#define DIRLIST_BADPARAM    0x02
#define DIRLIST_OVERFLOW    0x03
#define DIRLIST_BADENVVAL   0x04
#define DIRLIST_NOMOREITEMS 0x05
#ifndef uint32_t
#define uint32_t DWORD
#endif

typedef struct _USER_DIR_INFO {
    uint32_t depth;
    char*    startPath;
    char*    outfile;
    uint32_t outsize;
    FILE*    hFile;
} USER_DIR_INFO, *PUSER_DIR_INFO;

uint32_t dirlist_init(PUSER_DIR_INFO* ctx, char* outfile, uint32_t depth)
{
    PUSER_DIR_INFO usr = NULL;
    char*          tmp = NULL;
    size_t         outsize = 0;

    if(NULL == ctx || NULL == outfile) {
        printf("[x] Invalid arguments provided!\n");
        return DIRLIST_BADPARAM;
    }

    if(NULL == (usr = (PUSER_DIR_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(USER_DIR_INFO)))) {
        printf("[x] Out of memory!\n");
        return DIRLIST_NOMEMORY;
    }

    if(NULL == (tmp = getenv("HOMEPATH"))) {
        printf("[x] Unable to locate 'HOMEPATH'!\n");
        return DIRLIST_BADENVVAL;
    }

    usr->startPath = tmp;
    outsize = strlen(outfile);
    if(NULL == (tmp = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, outsize + 1))) {
        printf("[x] Out of memory!\n");
        HeapFree(GetProcessHeap(), 0, usr);
        return DIRLIST_NOMEMORY;
    }

    strcpy(tmp, outfile);
    usr->outfile = tmp;
    usr->outsize = outsize;
    usr->depth = depth;
    *ctx = usr;

    return DIRLIST_SUCCESS;
}

void dirlist_free(PUSER_DIR_INFO ctx)
{
    if(NULL == ctx)
        return;

    if(NULL != ctx->outfile)
        HeapFree(GetProcessHeap(), 0, ctx->outfile);

    if(NULL != ctx->hFile)
        fclose(ctx->hFile);
    HeapFree(GetProcessHeap(), 0, ctx);
}

uint32_t listing(PWIN32_FIND_DATA data, PUSER_DIR_INFO ctx, HANDLE hf, char* buf, uint32_t bufsz, uint32_t depth, uint32_t tab)
{
    WIN32_FIND_DATA innerData = {0};
    char innerBuf[MAX_PATH + 1] = {0};
    char tabBuf[MAX_PATH] = {0};
    HANDLE hInner = INVALID_HANDLE_VALUE;
    char* tmp = NULL;
    uint32_t i = 0;

    if(NULL == data || 0 == ctx->depth)
        return DIRLIST_NOMOREITEMS;
    for(; i < MAX_PATH && i < tab; ++i)
        tabBuf[i] = '\t';
    do {
        if((data->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && (data->cFileName[0] != '.')) {
            if(NULL != (tmp = strstr(buf, "*.*"))) {
                *tmp = '\0';
            }
            _snprintf(innerBuf, MAX_PATH, "%s%s\\*.*", buf, data->cFileName);
            if (INVALID_HANDLE_VALUE == (hInner = FindFirstFileA(innerBuf, &innerData))) {
                continue;
            }
            fprintf(ctx->hFile, "%s%s", tabBuf, data->cFileName);
            listing(data, ctx, hInner, innerBuf, MAX_PATH, depth - 1, tab + 1);
            FindClose(hInner);
        } else {
            fprintf(ctx->hFile, "%sFile | size: %s | %d bytes.\n", tabBuf, data->cFileName, data->nFileSizeLow);
        }
    } while(FindNextFileA(hf, data));
    
    return DIRLIST_NOMOREITEMS;

}

uint32_t __stdcall do_work(PUSER_DIR_INFO ctx)
{
    WIN32_FIND_DATA data = {0};
    uint32_t        status = 0;
    char            buf[MAX_PATH+1] = {0};
    char*           dirlist = NULL;
    HANDLE          hFile = NULL;

    if(NULL == ctx || NULL == ctx->startPath || NULL == ctx->outfile)
        return DIRLIST_BADPARAM;

    if(NULL == (ctx->hFile = fopen(ctx->outfile, "w"))) {
        printf("[x] Failed to open logfile!\n");
        return GetLastError();
    }

    _snprintf(buf, MAX_PATH, "%s\\*.*", ctx->startPath);
    if(INVALID_HANDLE_VALUE == (hFile = FindFirstFileA(buf, &data))) {
        printf("[x] First file not found!\n");
        return GetLastError();
    }

    ctx->depth += 1;
    if(DIRLIST_NOMOREITEMS != (status = listing(&data, ctx, hFile, buf, MAX_PATH, ctx->depth, 0))) {
        FindClose(hFile);
        return status;
    }

    FindClose(hFile);
    return DIRLIST_SUCCESS;
}


int __cdecl main(int argc, char** argv, char** envp)
{
	PUSER_DIR_INFO  info = NULL;
    HANDLE          hThread = NULL;
    uint32_t        status = 0;
    uint32_t        depth = 0;

    if(argc < 2 || (0 == (depth = strtoul(argv[1], NULL, 0)))) {
        depth = 10;
    }

    if(DIRLIST_SUCCESS != (status = dirlist_init(&info, OUTPATH, depth))) {
        return status;
    }

    if(NULL == (hThread = CreateThread(NULL, 0, do_work, info, 0, NULL))) {
        printf("[x] Failed to start running our worker! :(\n");
        return GetLastError();
    }

    WaitForSingleObject(hThread, INFINITE);
    dirlist_free(info);
    CloseHandle(hThread);
    return 0;
}