def algo(num_1, num_2):
	if int(num_2, 2) == 2:
		num_1 = twee(num_1)
	elif int(num_2, 2) == 3:
		num_1 = drie(num_1)
	else:
		num_1 = make8(num_1[2:])
	
	return num_1

def drie(num_1):
	return bin(int(twee(num_1), 2) ^ int(num_1, 2))[2:]

def twee(num_1):
	bin_a = bin(int(str(num_1), 2))[2:]

	bin_a = make8(bin_a)

	if bin_a[0] == '0':
		return bin(int(bin_a, 2) * 2)[2:]

	bin_a = leftshift(bin_a)
	bin_a = make8(bin_a)

	return bin(int(bin_a, 2) ^ 0b00011011)[2:]

def leftshift(num_1):
	return bin(int(num_1, 2) << 1)[2:]

def make8(num_1):
	if len(num_1) > 8:
		while len(num_1) != 8:
			num_1 = num_1[1:]
		
		return num_1
	elif len(num_1) == 8:
		return num_1
	else:
		while len(num_1) != 8:
			num_1 = '0' + num_1
		
		return num_1

g = [["2", "3", "1", "1"], ["1", "2", "3", "1"], ["1", "1", "2", "3"], ["3", "1", "1", "2"]]
a = ["db", "13", "53", "45"]

for i in range(len(g[1])):
	n1 = algo(bin(int(a[0], 16)), bin(int(g[i][0], 16)))
	n2 = algo(bin(int(a[1], 16)), bin(int(g[i][1], 16)))
	n3 = algo(bin(int(a[2], 16)), bin(int(g[i][2], 16)))
	n4 = algo(bin(int(a[3], 16)), bin(int(g[i][3], 16)))

	n = int(n1, 2) ^ int(n2, 2) ^ int(n3, 2) ^ int(n4, 2)
	print(hex(n)[2:])
