from RoundKeys import *
from MixCol import *
from SubBytesInv import *
from ShiftRows import *

"""
	the matrix has to be a square matrix with hex value
"""
def xor(matrix1, matrix2):
	new_matrix = make_empty_matrix(nb_rows=4)

	for i in range(len(matrix1)):
		for k in range(len(matrix1[0])):
			new_matrix[i].append(matrix1[i][k] ^ matrix2[i][k])

	return new_matrix

"""
	the key and decrypted_message are a list in a list structure
	round_keys is a dictionary where the keys are roundi with i the specific round and the values the round key
	round0 is the orginal key
"""
def decrypt_wpa2_data(encrypted_message, key, rounds=10):
	round_keys = make_key_streams(key, rounds)

	for i in range(rounds, -1, -1):
		print("round: " + i)
		print(encrypted_message)
		print(round_keys)
		# i = 10 tot en met 0
		if i == 10:
			encrypted_message = xor(round_keys['round10'], encrypted_message)
			encrypted_message = shift_matrix_row(encrypted_message)
			encrypted_message = sub_bytes_inv(encrypted_message)
		elif i == 0:
			decrypted_message = xor(round_keys['round0'], encrypted_message)
		else:
			encrypted_message = xor(round_keys['round{}'.format(i)], encrypted_message)
			encrypted_message = mix_col_inv(encrypted_message)
			encrypted_message = shift_matrix_row(encrypted_message)
			encrypted_message = sub_bytes_inv(encrypted_message)

	return decrypted_message

def key_to_matrix(key):
	"""
		- param key: a string
		- return: matrix
	"""
	matrix = []
	row=[]

	# Aanpassen naar (4x4)*n zodat het altijd vierkanten zijn, of whatever de bedoeling is.

	for elem in key:
		if len(row) == 4:
			matrix.append(row)
			row = []
		row.append(ord(elem))
		
	while len(row) != 0:
		row.append(0)

	matrix.append(row)

	if len(matrix) == 5:
		matrix.append([0, 0, 0, 0])

	new_matrix = []

	for i in range(len(matrix[0])):
		new_matrix.append([])

		for j in range(len(matrix)):
			new_matrix[i].append(matrix[j][i])

	return new_matrix