def algo(encrypted_vector):
	s = [0x0, 0x0, 0x0, 0x0]			# Decrypted vector
	a = encrypted_vector		# Encrypted vector from i.g., AERRijndeal.c

	q = [[0x0e, 0x0b, 0x0d, 0x09],
		[0x09, 0x0e, 0x0b, 0x0d],
		[0x0d, 0x09, 0x0e, 0x0b],
		[0x0b, 0x0d, 0x09, 0x0e]]		# Is inv(GF(2^8))

	# Calculating the whole matrix-vector product
	for i in range(len(a)):
		s[i] = hex(int(decrypt(q[i], a, s), 2))

	return s

def decrypt(q, a, s):
	result = ''
	polynomials_after_multiplication_and_longDiv = []

	for i in range(len(q)):
		# Convert hex to bin and stripping the 0b prefix in order to simplify later calculations.
		q_bin = bin(q[i])[2:]
		a_bin = bin(a[i])[2:]

		# Multiplication of a row in q and vector a, in GF(2^8)
		polynomial = multiplication(q_bin, a_bin)

		# Add the GF(2^8) vector to the placeholder for later addition modulo 2
		polynomials_after_multiplication_and_longDiv.append(longDiv(polynomial))

	# Make equal length to simplify calculations
	polynomials, l = makeEqualLengthFront(polynomials_after_multiplication_and_longDiv)

	# Addition with modulo 2 (xor)
	result = summate(polynomials, l)

	return result

def multiplication(q, a):
	# Every q-polynomial is multiplied with a term of a, with a leftshift of the power in this case
	polynomials = []

	for i in range(-1, -len(q) - 1, -1):
		if q[i] == '0':
				continue
		
		# Leftshift
		polynomials.append(bin(int(a, 2) << -i - 1)[2:])

	# Making it equal in length (for programming reasons)
	polynomials, maxLength = makeEqualLengthFront(polynomials)

	# Add the different polynomials to each other like one should when mannually calculating it
	polynomial = summate(polynomials, maxLength)

	return polynomial

def makeEqualLengthFront(polynomials):
	length = 0

	# Find max length in polynomials.
	for i in polynomials:
		if len(i) > length:
			length = len(i)

	# Add zeros in front of these polynomials.
	for i in range(len(polynomials)):
		while len(polynomials[i]) != length:
			polynomials[i] = '0' + polynomials[i]
		
	return polynomials, length

def makeEqualLengthBehind(polynomials):
	length = 0

	for i in polynomials:
		if len(i) > length:
			length = len(i)

	# Add zeros at the back until its as long as the longest polynomial
	for i in range(len(polynomials)):
		while len(polynomials[i]) != length:
			polynomials[i] += '0'

	return polynomials, length

def summate(polynomials, l = 0):
	polynomial = ''

	if l == 0:
		polynomials, l = makeEqualLengthBehind(polynomials)

	for i in range(l):
		count = 0

		for j in range(len(polynomials)):
			if polynomials[j][i] == '1':
				count += 1

		polynomial += str((count % 2))


	return stripZeroInFront(polynomial)
	
def stripZeroInFront(p):
	poly = ''

	for i in range(len(p)):
		if p[i] != '0': 
			return poly if len(poly) != 0 else p

		poly = p[i+1:]	

def longDiv(p):
	reducePoly = '100011011'

	if len(p) < len(reducePoly):
		return p
	
	while len(p) >= len(reducePoly):
		p = summate([p, reducePoly])
	
	return p

#algo([0x8e, 0x4d, 0xa1, 0xbc])
