from os.path import isfile
import hashlib

masterpass = input("Enter masterpass: ")
masterpass = hashlib.pbkdf2_hmac('sha256', str.encode(masterpass), str.encode("PyPassSalt73871"), 10000).hex()

filename = f"{masterpass[:3]}_passwords.pypass"
print("Masterpass hash:", masterpass)
print("Checking for file", filename)

if isfile(filename):
  print("file exists")
else:
  print("cant find file")
  data = bytes((122, 139, 10))
  print('writing')
  f = open(filename, 'wb')
  f.write(data)
  f.close()
  print('written')
