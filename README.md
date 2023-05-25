## Overview

Tool to generate shellcode loaders (exe, dll, or hta) for windows on mac/linux via mingw. Functions, variables, and encryption keys are randomly generated at runtime to hopefully avoid signatures.

## Requirements

##### Mac

1. Install mac ports - https://www.macports.org/install.php

2. `sudo port install mingw-w64`

3. `pip3 install pefile`

##### Linux (Debian)

1. `sudo apt install mingw-w64`

2. `pip3 install pefile`

## Usage 

```
┌─(frischfrischs-MBP)-[13:05:23]-[~/windows-payload-builder]
└─$ python3 jordanspecial.py -h
usage: main.py [-h] --build  --shellcode  [--etw] [--unhook] [--file] [--hide] [--user] --out

options:
  -h, --help    show this help message and exit
  --build       Choose 'exe', 'dll', or 'hta'
  --shellcode   File path to shellcode
  --etw         Patch the EtwEventWrite API
  --unhook      Dll name to unhook (S1 only hooks ntdll.dll)
  --file        Check if a file path exists as an execution guardrail
  --hide        Hide the console window then calculate prime numbers for ~20s (exe & hta only)
  --user        Check if the current user is the specified value as an execution guardrail
  --out         Name of output file

Example Usage:
    
python3 jordanspecial.py --build exe --shellcode /home/shellcode.bin --etw --unhook ntdll.dll --file "C:\Users\Admin\Desktop\file.txt" --hide --user Admin
```

## Detections

Uploading an executable containing Apollo shellcode yielded 2/71 detections as of 05/25/2023.

## Additional Notes

- Executables use WindowsCodecsRaw.dll for module stomping, if your shellcode exceeds the size of it's .text section your payload will fail. Consider changing the outputted source to use a different DLL instead if a 
larger DLL is needed for module stomping.
- Generated DLLs do not contain a DllMain export function, and thus cannot be used for DLL hijacking. Execute via `rundll32 dllname.dll,export_function`
   

## To Do
- [ ] Implement thread stack spoofing and/or memory fluctuation
- [ ] Add double ETW patching + other ETW APIs
- [ ] Add alternative execution options (NtCreateThreadEx + other callback functions)
- [ ] Add the option to unhook multiple DLLs
- [ ] Add the option to specify which DLL to module stomp
- [ ] Fix linux header includes (capitalization)
- [ ] Add DLLMain export for DLLs