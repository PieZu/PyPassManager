import hashlib
import base64
import pickle
import stringdist

from constants import SALT, MAX_EDIT_DISTANCE

PASSWORD_TYPES = ["hex", "Base64", "Deciml"]
DEFAULT_TYPE = "hex"


masterpass = ""

# store how many refreshes used, to make sure the same password isnt used twice
max_iterations = 0
passwords = []

### FUNCTIONS ###
def import_passwords(list):
  global passwords
  passwords = list

def set_masterpass(hash):
  global masterpass
  masterpass = hash

def find_password(name, error_correct=True):
  exact_match = list(filter(lambda x: x.name == name, passwords))
  if len(exact_match) != 0:
    # exact match(es) found, return it
    return exact_match[0]
  
  elif error_correct:
    # no exact match, check if any could've been typo'd
    for i in range(MAX_EDIT_DISTANCE):
      result = list(filter(lambda x: stringdist.rdlevenshtein(x.name, name) <= i+1, passwords))
      if len(result) == 1: # if theres exactly one (no ambiguity) return it
        return result[0]
  
  return "Not Found"

### CLASSES ###
class Password:
  def __init__(self, iteration="max", type=DEFAULT_TYPE, crop=False, name="__default"):
    # by default the password will start off with the next iteration after the max (.refresh will bring it up by 1). For some reason setting this directly in the parameter definition doesn't work when you change max_iterations dynamically. Weird.
    global max_iterations
    if iteration == "max": 
      iteration = max_iterations
    if name == "__default": # same thing with name wont work directly in the parameter
      name = "Pass"+str(iteration+1)

    # store settings
    self.change_type(type)
    self.change_crop(crop)
    self.change_name(name)
    self.iteration = iteration
    self.suffix = None

    # generate initial state
    self.refresh()
    
    #return self
  
  def change_name(self, name):
    if find_password(name, error_correct=False) == "Not Found":
      self.name = name
    else:
      raise UserWarning("Duplicate name:", name)
  
  def change_crop(self, crop_length):
    if crop_length != False: # 0 == False
        try: 
          crop_length = int(crop_length)
          self.crop_length = crop_length
        except ValueError:
          raise UserWarning("Crop length must be an integer or 0, unable to convert ", crop_length)
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
      
      if self.suffix:
        result += self.suffix
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
  
  def __getstate__(self):
    # don't pickle the hash representation - even if the save file encryption is broken it wont reveal the passwords (unless they're custom) 
    return (self.iteration, self.type, self.name, self.custom, self.crop_length, self.suffix)
  
  def __setstate__(self, state):
    (self.iteration, self.type, self.name, self.custom, self.crop_length, self.suffix) = state
    self.hash = hashlib.pbkdf2_hmac('sha256', masterpass, SALT, self.iteration)

    global max_iterations
    if self.iteration > max_iterations:
      max_iterations = self.iteration