import math
import pefile
import hashlib


def calcEntropy(data):

	entropy = 0
	if not data:
		return 0
	ent = 0
	for x in range(256):
		p_x = float(data.count(x))/len(data)
		if p_x > 0:
			entropy += - p_x*math.log(p_x, 2)
	return entropy

def entropy_check(file_name):
	pe = pefile.PE(file_name)
	for section in pe.sections:
		print("\t" + section.Name.decode('utf-8').strip('\\x00') + "\t" + str(calcEntropy(section.get_data())))
	print("[+] MD5: " + hashlib.md5(open(file_name, "rb").read()).hexdigest())


