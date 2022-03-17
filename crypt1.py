from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random

# to get public key:
# pub = key_pair.publickey().export_key()

# to get private key:
# priv = key_pair.export_key()

def generate_keys():

	# greating random bytes for key gen
	seed = Random.new().read

	# generate key pair with specified strength and seed
	key_pair = RSA.generate(2048, seed)

	# extracting public key from keypair and storing it in portably
	pub_key_PEM = key_pair.publickey().exportKey()
	### print(pub_key_PEM.decode('ascii'))
	with open("public.pem", "wb") as f:
		f.write(pub_key_PEM)


	# extracting private key from key pair and storing it portably
	priv_key_PEM = key_pair.exportKey()
	# print(priv_key_PEM.decode('ascii'))
	with open("private.pem", "wb") as f:
		f.write(priv_key_PEM)


def encrypt(text):

	# importing public key
	public_key = RSA.import_key(open("public.pem").read())
	
	# generating an encryptor using public key
	cipher_rsa = PKCS1_OAEP.new(public_key)

	# encrypting
	encrypted_text = cipher_rsa.encrypt(text)
	return encrypted_text


def decrypt(encrypted_text):
	
	# importing private key
	private_key = RSA.import_key(open("private.pem").read())

	# generating a decryptor using private key
	cipher_rsa = PKCS1_OAEP.new(private_key)
	
	# decrypting
	decrypted_text = cipher_rsa.decrypt(encrypted_text)
	return(decrypted_text)

def main():

	try:	

		text = input("Enter a string to be encrypted: ")
		while text:

			# generate key pair
			generate_keys()
			
			# encrytping text
			encrypted_text = encrypt(str.encode(text))
			print(f"\nEncrypted text: {encrypted_text}\n")

			# decrypting text
			decrypted_text = decrypt(encrypted_text)
			print(f"\nDecrypted text: {(decrypted_text).decode()}\n")

			# get user input again
			text = input("Enter a string to be encrypted:")

	except KeyboardInterrupt:
		return 1


main()