import pickle #rick. pickle is apparently pretty efficient
import bz2 # but can be efficiently compressed as well
import hashlib
import base64

SALT = b"PyPassSalt73871" # unique salt to counteract lookup tables
PASSWORD_TYPES = {"hex": 0, "Base64": 1, "Deciml": 3}
DEFAULT_TYPE = "hex"

class Password:
  def __init__(self, iteration="max", type=DEFAULT_TYPE, crop=False, name="__default", file=False):
    
    # by default the password will start off with the next iteration after the max (.refresh will bring it up by 1). For some reason setting this directly in the parameter definition doesn't work when you change max_iterations dynamically. Weird.
    if iteration == "max": 
      iteration = max_iterations
    if name == "__default": # same thing with name wont work directly in the parameter
      name = "Pass"+str(iteration+1)

    # store settings
    self.change_type(type)
    self.change_crop(crop)
    self.change_name(name)
    self.iteration = iteration

    # generate initial state
    self.refresh()
    
    #return self
  
  def change_name(self, name):
    if find_password(name) == "Not Found":
      self.name = name
    else:
      raise UserWarning("Duplicate name:", name)
  
  def change_crop(self, crop_length):
    if crop_length != False:
        try: 
          crop_length = int(crop_length)
          if crop_length < 0:
            raise UserWarning("Crop length must be greater than 0, not ", crop_length)
          else:
            self.crop_length = crop_length
        except ValueError:
          raise UserWarning("Crop length must be a number or False, unable to convert ", crop_length)
    else: 
      self.crop_length = False

  def change_type(self, type):
    if type not in PASSWORD_TYPES:
      raise UserWarning("Type", type, "not recognised. Valid types:", PASSWORD_TYPES)
    else:
      self.type = type

  def refresh(self):
    # iterate
    global max_iterations
    max_iterations += 1
    self.iteration = max_iterations

    self.custom = False

    # generate the passwords hash / source  
    self.hash = hashlib.pbkdf2_hmac('sha256', masterpass, SALT, self.iteration)
    
    return self

  def __repr__(self):
    # generate password plaintext with current settings
    if self.custom:
      return self.custom
    else:
      if self.type == "hex":
        result = self.as_hex()
      elif self.type == "Base64":
        result = self.as_base64()
      elif self.type == "Deciml":
        result = self.as_decimal()
      
      # apply cropping if provided
      if self.crop_length:
        result = result[:self.crop_length]
      
      return result
  
  def as_hex(self):
    return self.hash.hex()
  
  def as_bytearray(self):
    return bytes.fromhex(self.as_hex())

  def as_base64(self):
    number = base64.b64encode(self.as_bytearray())
    return number.decode()

  def as_decimal(self):
    number = int.from_bytes(self.as_bytearray(), 'big')
    return str(number)

  def delete(self):
    global max_iterations
    if max_iterations == self.iteration:
      max_iterations -= 1
    self.type = None
    self.name = None
    self.hash = None

  def pickle(self):
    return 

def find_password(name):
  result = list(filter(lambda x: x.name == name, passwords))
  if len(result) == 0:
    return "Not Found"
  else:
    return result[0]

masterpass = b"0101011"
max_iterations=0
passwords = []
for i in range(15):
  passwords.append(Password())
passwords[1].custom = "she'sabeaut"
passwords[2].refresh()
passwords[0].change_name("gottem")
passwords[0].change_type("Base64")
passwords[4].change_name("YouTube")
passwords[4].refresh().refresh().refresh().refresh().refresh()
"""
passwords[13].change_type("Deciml")
passwords[13].change_crop(18)
passwords[11].custom = "she'sabeaut"
passwords[12].refresh()
passwords[10].change_name("got333tem")
passwords[10].change_type("Base64")
passwords[14].change_name("YouT3ube")
passwords[14].refresh().refresh().refresh().refresh().refresh()
passwords[13].change_type("Deciml")
passwords[13].change_crop(18)
#"""

rick = pickle.dumps(passwords)

morty = bz2.compress(rick)


derick = bz2.decompress(morty)

demorty = pickle.loads(derick)

print(demorty)

print("Length of pickled:", len(str(rick)))
print("Length of unzipped zip of pickle:", len(str(derick)))

print("Length of zipped pickle:", len(str(morty)))