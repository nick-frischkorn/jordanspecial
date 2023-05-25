import random
from modules.namegen import generate_random_name


def generate_do_math(function_name):

    prime_stub = """
void REPLACE_WITH_FUNCTION_NAME() {

	int REPLACE_W_VAR1 = 0;
	int REPLACE_W_VAR2 = REPLACE_WITH_MAX_CALC; 
	bool REPLACE_W_VAR3 = false;

	for (int i = 2; i < REPLACE_W_VAR2; i++) {

		bool REPLACE_W_VAR4 = true;
		bool REPLACE_W_VAR5 = true;

		for (int j = 2; j * j <= i; j++)
		{
			if (i % j == 0)
			{
				REPLACE_W_VAR4 = false;
				if (REPLACE_W_VAR5 == true) {
					REPLACE_W_VAR5 == false;
				}
				break;
			}
			REPLACE_W_VAR1 = i;
			std::cout << " ";

			if (REPLACE_W_VAR3 == false) {
				if (i > REPLACE_WITH_HIDE_COUNT) {

					ShowWindow(GetConsoleWindow(), SW_HIDE);
					REPLACE_W_VAR3 = true;

				}
			}
		}
	}
}

"""
    prime_stub = prime_stub.replace("REPLACE_WITH_FUNCTION_NAME", function_name)
    prime_stub = prime_stub.replace("REPLACE_WITH_HIDE_COUNT", str(random.randint(250, 500)))
    prime_stub = prime_stub.replace("REPLACE_WITH_MAX_CALC", str(random.randint(25000, 50000)))

    prime_stub = prime_stub.replace("REPLACE_W_VAR1", generate_random_name())
    prime_stub = prime_stub.replace("REPLACE_W_VAR2", generate_random_name())
    prime_stub = prime_stub.replace("REPLACE_W_VAR3", generate_random_name())
    prime_stub = prime_stub.replace("REPLACE_W_VAR4", generate_random_name())
    prime_stub = prime_stub.replace("REPLACE_W_VAR5", generate_random_name())

    return prime_stub


