# *****************************************************************************
# \file test.py
# \project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
# \brief Python tests for openssl[bee2evp]
# \created 2019.07.10
# \version 2019.07.16
# \license This program is released under the GNU General Public License 
# version 3 with the additional exemption that compiling, linking, 
# and/or using OpenSSL is allowed. See Copyright Notices in bee2evp/info.h.
# *****************************************************************************

from openssl import openssl
from belt import *

def test_version():
	retcode, out, __ = openssl('version', '', True)
	assert retcode == 0
	print(out)

def test_engine():
	retcode, out, __ = openssl('engine -c -t bee2evp', '', True)
	assert retcode == 0
	print(out)

def test_belt():

	#Block (|X| = 128)
	#A.1 Encrypt
	block = 'b194bac80a08f53b366d008e584a5de4'.decode('hex')
	key = ('e9dee72c8f0c0fa62ddb49f46f739647' + '06075316ed247a3739cba38303a98bf6').decode('hex')
	block = beltBlockEncr(bytes(block), bytes(key))
	assert block.encode('hex') == '69cca1c93557c9e3d66bc3e0fa88fa6e'

	#A.4 Decrypt
	block = 'e12bdc1ae28257ec703fccf095ee8df1'.decode('hex')
	key = ('92bd9b1ce5d141015445fbc95e4d0ef2' + '682080aa227d642f2687f93490405511').decode('hex')
	block = beltBlockDecr(bytes(block), bytes(key))
	assert block.encode('hex') == '0dc5300600cab840b38448e5e993f421'
	
	#ECB (|X| = 384)
	#A.6 Encrypt
	src = ('b194bac80a08f53b366d008e584a5de4' + '8504fa9d1bb6c7ac252e72c202fdce0d' + '5be3d61217b96181fe6786ad716b890b').decode('hex')
	key = ('e9dee72c8f0c0fa62ddb49f46f739647' + '06075316ed247a3739cba38303a98bf6').decode('hex')
	dest = beltECBEncr(bytes(src), bytes(key))
	assert dest.encode('hex') == ('69cca1c93557c9e3d66bc3e0fa88fa6e' + '5f23102ef109710775017f73806da9dc' + '46fb2ed2ce771f26dcb5e5d1569f9ab0')

	#A.8 Decrypt	
	src = ('e12bdc1ae28257ec703fccf095ee8df1' + 'c1ab76389fe678caf7c6f860d5bb9c4f' + 'f33c657b637c306add4ea7799eb23d31').decode('hex')
	key = ('92bd9b1ce5d141015445fbc95e4d0ef2' + '682080aa227d642f2687f93490405511').decode('hex')
	dest = beltECBDecr(bytes(src), bytes(key))
	assert dest.encode('hex') == ('0dc5300600cab840b38448e5e993f421' + 'e55a239f2ab5c5d5fdb6e81b40938e2a' + '54120ca3e6e19c7ad750fc3531daeab7')

	#CBC (|X| = 384)
	#A.10 Encrypt
	src = ('b194bac80a08f53b366d008e584a5de4' + '8504fa9d1bb6c7ac252e72c202fdce0d' + '5be3d61217b96181fe6786ad716b890b').decode('hex')
	iv = 'be32971343fc9a48a02a885f194b09a1'.decode('hex')
	key = ('e9dee72c8f0c0fa62ddb49f46f739647' + '06075316ed247a3739cba38303a98bf6').decode('hex')
	dest = beltCBCEncr(bytes(src), bytes(key), bytes(iv))
	assert dest.encode('hex') == ('10116efae6ad58ee14852e11da1b8a74' + '5cf2480e8d03f1c19492e53ed3a70f60' + '657c1ee8c0e0ae5b58388bf8a68e3309')

	#A.12 Decrypt
	src = ('e12bdc1ae28257ec703fccf095ee8df1' + 'c1ab76389fe678caf7c6f860d5bb9c4f' + 'f33c657b637c306add4ea7799eb23d31').decode('hex')
	iv = '7ecda4d01544af8ca58450bf66d2e88a'.decode('hex')
	key = ('92bd9b1ce5d141015445fbc95e4d0ef2' + '682080aa227d642f2687f93490405511').decode('hex')
	dest = beltCBCDecr(bytes(src), bytes(key), bytes(iv))
	assert dest.encode('hex') == ('730894d6158e17cc1600185a8f411cab' + '0471ff85c83792398d8924ebd57d03db' + '95b97a9b7907e4b020960455e46176f8')

	#CFB (|X| = 384)
	#A.14 Encrypt
	src = ('b194bac80a08f53b366d008e584a5de4' + '8504fa9d1bb6c7ac252e72c202fdce0d' + '5be3d61217b96181fe6786ad716b890b').decode('hex')
	iv = 'be32971343fc9a48a02a885f194b09a1'.decode('hex')
	key = ('e9dee72c8f0c0fa62ddb49f46f739647' + '06075316ed247a3739cba38303a98bf6').decode('hex')
	dest = beltCFBEncr(bytes(src), bytes(key), bytes(iv))
	assert dest.encode('hex') == ('c31e490a90efa374626cc99e4b7b8540' + 'a6e48685464a5a06849c9ca769a1b0ae' + '55c2cc5939303ec832dd2fe16c8e5a1b')

	#A.15 Decrypt
	src = ('e12bdc1ae28257ec703fccf095ee8df1' + 'c1ab76389fe678caf7c6f860d5bb9c4f' + 'f33c657b637c306add4ea7799eb23d31').decode('hex') 
	iv = '7ecda4d01544af8ca58450bf66d2e88a'.decode('hex')
	key = ('92bd9b1ce5d141015445fbc95e4d0ef2' + '682080aa227d642f2687f93490405511').decode('hex')
	dest = beltCFBDecr(bytes(src), bytes(key), bytes(iv))
	assert dest.encode('hex') == ('fa9d107a86f375ee65cd1db881224bd0' + '16aff814938ed39b3361abb0bf0851b6' + '52244eb06842dd4c94aa4500774e40bb')

	#CTR (|X| = 384)
	#A.16
	src = ('b194bac80a08f53b366d008e584a5de4' + '8504fa9d1bb6c7ac252e72c202fdce0d' + '5be3d61217b96181fe6786ad716b890b').decode('hex')
	iv = 'be32971343fc9a48a02a885f194b09a1'.decode('hex')
	key = ('e9dee72c8f0c0fa62ddb49f46f739647' + '06075316ed247a3739cba38303a98bf6').decode('hex')
	dest = beltCTREncr(bytes(src), bytes(key), bytes(iv))
	assert dest.encode('hex') == ('52c9af96ff50f64435fc43def56bd797' + 'd5b5b1ff79fb41257ab9cdf6e63e81f8' + 'f00341473eae409833622de05213773a')

	#MAC
	#A.18
	src = ('b194bac80a08f53b366d008e584a5de4' + '8504fa9d1bb6c7ac252e72c202fdce0d' + '5be3d61217b96181fe6786ad716b890b').decode('hex')
	key = ('e9dee72c8f0c0fa62ddb49f46f739647' + '06075316ed247a3739cba38303a98bf6').decode('hex')
	mac = beltMAC(bytes(src), bytes(key))
	assert mac.encode('hex') == '2dab59771b4b16d0'

	#HASH
	#A.25
	src = ('b194bac80a08f53b366d008e584a5de4' + '8504fa9d1bb6c7ac252e72c202fdce0d').decode('hex')
	hash_ = beltHash(bytes(src))
	assert hash_.encode('hex') == ('749e4c3653aece5e48db4761227742eb' + '6dbe13f4a80f7beff1a9cf8d10ee7786')


if __name__ == '__main__':
	test_version()
	test_engine()
	test_belt()

	
