import hashlib

def xor(plaintext, key):
  cyphertext = bytearray()
  for i in range(len(plaintext)):
    cyphertext.append(plaintext[i] ^ key[i%len(key)])
  return bytes(cyphertext)

def binary(array):
  return "".join([bin(int(i))[2:] for i in array])

def show_xor(a, b, crop=80):
  print("")
  print(" ", binary(a)[:crop], "...")
  print("^", binary(b)[:crop], "...")
  c = xor(a,b)
  print("-"*(crop+6))
  print("=", binary(c)[:crop], "...")
  return c

masterpass = hashlib.pbkdf2_hmac('sha512', str.encode("example"), str.encode("PyPassSalt73871"), 10000)

a = b'{"Example bytestring": 3}' # can be longer than key/masterpass, but short here for less messy print example

print("plaintext:", a)
print("plaintext binary:", binary(a))

print("XOR key:", masterpass)
print("XOR key binary:", binary(masterpass))

enc = show_xor(a,masterpass)
back = show_xor(enc,masterpass)

print("decrypted:", back)
print("decrypted binary:", binary(back))