from Crypto.Cipher import AES
from os import urandom

def pad(txt):
  "AES CBC requires the number of plaintext bytes to be a multiple of 16, so we pad it to the nearest multiple. Takes&Returns bytes object."
  padding_length = AES.block_size - len(txt)%AES.block_size
  # we pad with a character = to the padding length, to make unpadding easy
  padding = chr(padding_length) * padding_length

  return txt+padding.encode()
 
def unpad(txt):
  "To get just the encrypted data back, we need to undo any meaningless padding we added to satisfy length requirements. Takes&Returns bytes object."
  padding_length = txt[-1] # length is stored as the character code of the padding
  return txt[:-padding_length]

def encrypt(raw, key):
  "Encrypt bytes using AES CBC, and a random InitialVector that is stored at the start. Inputs two bytes objects: plaintext & key. Returns ciphertext as bytes object."
  iv = urandom(AES.block_size)
  key = key[:32] # key must be 32 bytes, masterpass hash is 64 bytes
  cipher = AES.new(key, AES.MODE_CBC, iv)

  return iv+cipher.encrypt(pad(raw)) # store iv so it can be decoded

def decrypt(data, key):
  "Decrypt bytes using AES CBC, extracting the InitialVector from the start. Inputs two bytes objects: ciphertext & key. Returns plaintext as bytes object."
  iv, data = data[:AES.block_size], data[AES.block_size:] # extract the iv from the start
  key = key[:32] # key must be 32 bytes, masterpass hash is 64 bytes
  cipher = AES.new(key, AES.MODE_CBC, iv)
  return unpad(cipher.decrypt(data))