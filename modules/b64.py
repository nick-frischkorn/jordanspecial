import base64
from textwrap import wrap

def b64_encode_dll(dll_file_path):
    file_text = open(dll_file_path, 'rb')
    file_read = file_text.read()
    file_encode = base64.b64encode(file_read).decode('ascii')

    out = wrap(file_encode, 100)

    payload = "payload = \"\";\n"
    for i in out:
        payload += "\t\tpayload = payload + \"" + i + "\";\n"

    return payload