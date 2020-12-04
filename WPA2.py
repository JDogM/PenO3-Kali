from RoundKeys import *
from MixCol import *
from SubBytesInv import *
from ShiftRows import *
from binascii import *


"""
	the matrix has to be a square matrix with hex value
"""
def make_matrix(encrypted_message) :
    #hex_string = encrypted_message.decode('utf-8')
    hex_string = encrypted_message
    while len(hex_string) % 32 != 0 :
        hex_string += '0'

    nb_matrices = len(hex_string) // 32
    matrices = []

    for i in range(nb_matrices) :
        matrix_content = hex_string[i * 32 :i * 32 + 32]
        matrix = [[], [], [], []]

        for col in range(4) :
            for row in range(4) :
                pair = matrix_content[:2]
                matrix_content = matrix_content[2:]
                matrix[row].append(int(pair, 16))

        matrices.append(matrix)

    return matrices

def xor(matrix1, matrix2) :
    new_matrix = make_empty_matrix(nb_rows=4)

    for i in range(len(matrix1)) :
        for k in range(len(matrix1[0])) :
            new_matrix[i].append(matrix1[i][k] ^ matrix2[i][k])

    return new_matrix

"""
	the key and decrypted_message are a list in a list structure
	round_keys is a dictionary where the keys are roundi with i the specific round and the values the round key
	round0 is the orginal key
"""
def matrix_to_string(matrix) :
    string = ""
    for col in range(len(matrix)) :
        for row in range(len(matrix)) :
            string += chr(matrix[row][col])
    return string

def key_to_matrix(key):
    """
		- param key: a string
		- return: matrix
    """
    matrix = [[], [], [], []]

    for col in range(4):
        for row in range(4):
            pair = key[:2]
            key = key[2:]
            matrix[row].append(int(pair, 16))

    return matrix

def encrypt_wpa2_data(decrypted_message, round_keys, rounds = 10):
    for message in decrypted_message:
        for i in range(rounds+1):
            if i == 0:
                message = xor(round_keys['round0'], message)
            elif i == rounds:
                message = sub_bytes(message)
                message = shift_matrix_row(message)
                message = xor(round_keys['round10'], message)
            else:
                message = sub_bytes(message)
                message = shift_matrix_row(message)
                message = mix_col(message)
                message = xor(round_keys['round{}'.format(i)], message)
    return message

def decrypt_wpa2_data(encrypted_message, round_keys, rounds=10) :
    for message in encrypted_message:
        for i in range(rounds, -1, -1) :
            if i == rounds:
                message = xor(round_keys['round10'], message)
                message = shift_matrix_row_inv(message)
                message = sub_bytes_inv(message)
            elif i == 0:
                decrypted_message = xor(round_keys['round0'], message)
            else:
                message = xor(round_keys['round{}'.format(i)], message)
                message = mix_col_inv(message)
                message = shift_matrix_row_inv(message)
                message = sub_bytes_inv(message)

    return decrypted_message


