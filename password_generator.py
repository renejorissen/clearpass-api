#!/usr/bin/env python3
#------------------------------------------------------------------------------
#
# Password Generator
#
#------------------------------------------------------------------------------

import random
import string

def password():
    uppercase = (string.ascii_uppercase)
    lowercase = (string.ascii_lowercase)
    number = (string.digits)
    symbols = (string.punctuation)

    strong = uppercase + lowercase + number + symbols

    generated_password = "".join(random.sample(strong, 15))
    print(generated_password)

if __name__ == "__main__":
    password()