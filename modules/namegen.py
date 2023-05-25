import random
import string


def generate_random_name():
    letters = string.ascii_letters
    name = ""
    for i in range(random.randint(10, 16)):
        letter = random.choice(letters)
        name = name + letter
    return name