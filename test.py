# =====================================================================================================# word = "0123456"
# h_index = 0
# e_index = 1
# tester = ''
#
# if len(word) % 2 == 0:
#     for _ in range(len(word) // 2):
#         tester += word[h_index]
#         tester += word[e_index]
#         h_index += 2
#         e_index += 2
# else:
#     for _ in range(len(word) // 2 + 1):
#         tester += word[h_index]
#         if e_index < len(word):
#             tester += word[e_index]
#         h_index += 2
#         e_index += 2
#
# print(tester)
import os


# =====================================================================================================
def string_to_number(s):
    # Convert each character to its ASCII code, add 100, and join them with zeros
    # Use modulo 256 to wrap the values around the range of 0-255
    return int("".join(str((ord(c) + 100) % 256).zfill(3) for c in s))

def number_to_string(n):
    n_str = str(n)
    # Split the number into groups of three digits, subtract 100, and convert them to characters
    # Use modulo 256 to wrap the values around the range of 0-255
    chunks = [n_str[i:i+3] for i in range(0, len(n_str), 3)]
    return "".join(chr((int(chunk) - 100) % 256) for chunk in chunks)


# # Test
# import sys
# sys.set_int_max_str_digits(100000000)
#
# with open('1.txt', 'r', encoding='utf-8') as f:
#     contents = f.read()
#     n = string_to_number(contents)
#     m = number_to_string(n)
#     print(len(str(n)))
#     print(len(contents))
    # print(m)
    # print(m == contents)

# import time
# file_list = []
# s2n_time = {}
# n2s_time = {}
# validity = {}
# for file_name in os.listdir():
#     if file_name.endswith('.txt'):
#         file_list.append(file_name)
# for i in file_list:
#     with open(i, 'r', encoding='utf-8') as f:
#         print('=', end='')
#         contents = f.read()
#         s2n_start = time.time()
#         n = string_to_number(contents)
#         s2n_end = time.time()
#         s2n_time[i] = f'{s2n_end - s2n_start} s'
#
#         n2s_start = time.time()
#         m = number_to_string(n)
#         n2s_end = time.time()
#         n2s_time[i] = f'{n2s_end - n2s_start} s'
#
#         validity[i] = (m == contents)
# print("___________________ String To Number ___________________\n")
# print('\n'.join(f'{file} :: {times}' for file, times in s2n_time.items()))
# print("___________________ Number To String ___________________\n")
# print('\n'.join(f'{file} :: {times}' for file, times in n2s_time.items()))
# print("___________________ Validity ___________________\n")
# print('\n'.join(f'{file} :: {valid}' for file, valid in validity.items()))

import string
import random

def _generate_random_string(length):
    characters = string.ascii_letters + string.digits
    random_string = ''.join(random.choice(characters) for _ in range(length))
    return random_string

print(_generate_random_string(16))

