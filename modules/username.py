from modules.namegen import generate_random_name


def generate_username_check(function_name, user):

    username_stub = """
void REPLACE_WITH_FUNCTION_NAME() {

    TCHAR REPLACE_W_VAR1[60];
	DWORD REPLACE_W_VAR2[60];
	
	GetUserName(REPLACE_W_VAR1, REPLACE_W_VAR2);
	if (std::string(REPLACE_W_VAR1).compare("REPLACE_W_USERNAME") == 1) {
		exit(0);
	}

}

"""

    username_stub = username_stub.replace("REPLACE_WITH_FUNCTION_NAME", function_name)
    username_stub = username_stub.replace("REPLACE_W_USERNAME", user)

    username_stub = username_stub.replace("REPLACE_W_VAR1", generate_random_name())
    username_stub = username_stub.replace("REPLACE_W_VAR2", generate_random_name())

    return username_stub