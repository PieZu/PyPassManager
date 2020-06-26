from os.path import isfile
import hashlib

masterpass = input("Enter masterpass: ")
masterpass = hashlib.pbkdf2_hmac('sha256', str.encode(masterpass), str.encode("PyPassSalt73871"), 10000).hex()

filename = f"{masterpass[:3]}_passwords.pypass"
print("Masterpass hash:", masterpass)
print("Checking for file", filename)

if isfile(filename):
  print("file exists")

  print("reading")
  with open(filename, mode='rb') as file:
    fileContent = file.read()
    print("Data read:", fileContent)

else:
  print("file not found")
  
  data = input("Data to save: ").encode("utf-8")

  print('writing')

  with open(filename, mode='wb') as file:
    file.write(data)
  
  print('written')
