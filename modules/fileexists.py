from modules.namegen import generate_random_name

def generate_file_exist_stub(function_name, file_path):

    file_exist_stub = """
void REPLACE_WITH_FUNCTION_NAME() {

    LPCSTR REPLACE_W_VAR1 = "REPLACE_WITH_FILE_PATH";
    if (PathFileExistsA(REPLACE_W_VAR1))
    {
        return;
    }
    else
    {
        exit(0);
    }
}

"""
    correct_file_path = file_path.replace('\\', "\\\\")
    file_exist_stub = file_exist_stub.replace("REPLACE_WITH_FUNCTION_NAME", function_name)
    file_exist_stub = file_exist_stub.replace("REPLACE_WITH_FILE_PATH", correct_file_path)
    file_exist_stub = file_exist_stub.replace("REPLACE_W_VAR1", generate_random_name())

    return file_exist_stub