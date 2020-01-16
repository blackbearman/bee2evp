from openssl import openssl, OPENSSL_EXE_PATH

ECHO_EXE_PATH = '/bin/echo'

def beltBlockEncr(block, key):
	assert len(block) * 8 == 128

	plain = block.encode('base64')
	key = key.encode('hex')
	key_bitlen = len(key) * 4

	prefix = ECHO_EXE_PATH + ' ' + plain[:-1] + ' | ' + OPENSSL_EXE_PATH + ' enc -d -base64 |'
	cmd = 'enc -e -belt-ecb{} -nosalt -nopad -K {}'.format(key_bitlen, key)
	retcode, block, er__ = openssl(cmd, prefix, True)
	return block

def beltBlockDecr(block, key):
	assert len(block) * 8 == 128

	plain = block.encode('base64')
	key = key.encode('hex')
	key_bitlen = len(key) * 4

	prefix = ECHO_EXE_PATH + ' ' + plain[:-1] + ' | ' + OPENSSL_EXE_PATH + ' enc -d -base64 |'
	cmd = 'enc -d -belt-ecb{} -nosalt -nopad -K {}'.format(key_bitlen, key)
	retcode, block, er__ = openssl(cmd, prefix, True)
	return block

def beltECBEncr(src, key):
	assert (len(src) * 8) % 128 == 0

	plain = src.encode('base64')
	key = key.encode('hex')
	key_bitlen = len(key) * 4

	prefix = ECHO_EXE_PATH + ' ' + plain[:-1] + ' | ' + OPENSSL_EXE_PATH + ' enc -d -base64 |'
	cmd = 'enc -e -belt-ecb{} -nosalt -nopad -K {}'.format(key_bitlen, key)
	retcode, dest, er__ = openssl(cmd, prefix, True)
	return dest

def beltECBDecr(src, key):
	assert (len(src) * 8) % 128 == 0

	plain = src.encode('base64')
	key = key.encode('hex')
	key_bitlen = len(key) * 4

	prefix = ECHO_EXE_PATH + ' ' + plain[:-1] + ' | ' + OPENSSL_EXE_PATH + ' enc -d -base64 |'
	cmd = 'enc -d -belt-ecb{} -nosalt -nopad -K {}'.format(key_bitlen, key)
	retcode, dest, er__ = openssl(cmd, prefix, True)
	return dest	

def beltCBCEncr(src, key, iv):
	assert (len(src) * 8) % 128 == 0

	plain = src.encode('base64')
	key = key.encode('hex')
	iv = iv.encode('hex')
	key_bitlen = len(key) * 4

	prefix = ECHO_EXE_PATH + ' ' + plain[:-1] + ' | ' + OPENSSL_EXE_PATH + ' enc -d -base64 |'
	cmd = 'enc -e -belt-cbc{} -nosalt -nopad -K {} -iv {}'.format(key_bitlen, key, iv)
	retcode, dest, er__ = openssl(cmd, prefix, True)
	return dest

def beltCBCDecr(src, key, iv):
	assert (len(src) * 8) % 128 == 0

	plain = src.encode('base64')
	key = key.encode('hex')
	iv = iv.encode('hex')
	key_bitlen = len(key) * 4

	prefix = ECHO_EXE_PATH + ' ' + plain[:-1] + ' | ' + OPENSSL_EXE_PATH + ' enc -d -base64 |'
	cmd = 'enc -d -belt-cbc{} -nosalt -nopad -K {} -iv {}'.format(key_bitlen, key, iv)
	retcode, dest, er__ = openssl(cmd, prefix, True)
	return dest

def beltCFBEncr(src, key, iv):
	assert (len(src) * 8) % 128 == 0

	plain = src.encode('base64')
	key = key.encode('hex')
	iv = iv.encode('hex')
	key_bitlen = len(key) * 4

	prefix = ECHO_EXE_PATH + ' ' + plain[:-1] + ' | ' + OPENSSL_EXE_PATH + ' enc -d -base64 |'
	cmd = 'enc -e -belt-cfb{} -nosalt -nopad -K {} -iv {}'.format(key_bitlen, key, iv)
	retcode, dest, er__ = openssl(cmd, prefix, True)
	return dest

def beltCFBDecr(src, key, iv):
	assert (len(src) * 8) % 128 == 0

	plain = src.encode('base64')
	key = key.encode('hex')
	iv = iv.encode('hex')
	key_bitlen = len(key) * 4

	prefix = ECHO_EXE_PATH + ' ' + plain[:-1] + ' | ' + OPENSSL_EXE_PATH + ' enc -d -base64 |'
	cmd = 'enc -d -belt-cfb{} -nosalt -nopad -K {} -iv {}'.format(key_bitlen, key, iv)
	retcode, dest, er__ = openssl(cmd, prefix, True)
	return dest

def beltCTREncr(src, key, iv):
	assert (len(src) * 8) % 128 == 0

	plain = src.encode('base64')
	key = key.encode('hex')
	iv = iv.encode('hex')
	key_bitlen = len(key) * 4

	prefix = ECHO_EXE_PATH + ' ' + plain[:-1] + ' | ' + OPENSSL_EXE_PATH + ' enc -d -base64 |'
	cmd = 'enc -e -belt-ctr{} -nosalt -nopad -K {} -iv {}'.format(key_bitlen, key, iv)
	retcode, dest, er__ = openssl(cmd, prefix, True)
	return dest

def beltCTRDecr(right_plain_msg, right_enc_msg, key, msg_len, iv):
	assert (len(src) * 8) % 128 == 0

	plain = src.encode('base64')
	key = key.encode('hex')
	iv = iv.encode('hex')
	key_bitlen = len(key) * 4

	prefix = ECHO_EXE_PATH + ' ' + plain[:-1] + ' | ' + OPENSSL_EXE_PATH + ' enc -d -base64 |'
	cmd = 'enc -d -belt-ctr{} -nosalt -nopad -K {} -iv {}'.format(key_bitlen, key, iv)
	retcode, dest, er__ = openssl(cmd, prefix, True)
	return dest

def beltMAC(src, key):
	plain = src.encode('base64')
	key = key.encode('hex')
	key_bitlen = len(key)*4
	
	prefix = ECHO_EXE_PATH + ' ' + plain[:-1] + ' | ' + OPENSSL_EXE_PATH + ' enc -d -base64 |'
	cmd = 'dgst -mac belt-mac{} -macopt hexkey:{}'.format(256, key)
	retcode, out, er__ = openssl(cmd, prefix, True)
	mac = bytes((out.split(' ')[1][:-1]).decode('hex'))
	return mac
	
def beltHash(src):
	plain = src.encode('base64')

	prefix = ECHO_EXE_PATH + ' ' + plain[:-1] + ' | ' + OPENSSL_EXE_PATH + ' enc -d -base64 |'
	cmd = 'dgst -belt-hash'.format()
	retcode, out, er__ = openssl(cmd, prefix, True)
	hash_ = bytes((out.split(' ')[1][:-1]).decode('hex'))
	return hash_