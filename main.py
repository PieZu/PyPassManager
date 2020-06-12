import hashlib

# get master password
masterpass = input("Enter your master password:\n")

# convert into bytes so that it can be hashed
masterpass = str.encode(masterpass)

# turn plaintext password to hash, unreversable
salt = b"PyPassSalt73871" # unique salt to counteract lookup tables
masterpass = hashlib.pbkdf2_hmac('sha512', masterpass, salt, 10000)

# store how many refreshes used, to make sure the same password isnt used twice
max_iterations = 1

class Password:
  def __init__(self, iteration="max", type="hex", crop=False):

    # by default the password will start off with the next iteration after the max (.refresh will bring it up by 1). For some reason setting this directly in the parameter definition doesn't work when you change max_iterations dynamically. Weird.
    if iteration == "max": 
      iteration = max_iterations

    # store settings
    self.type = type
    self.crop_length = crop
    self.iteration = iteration

    # generate initial state
    self.refresh()
    
    #return self
  
  def refresh(self):
    # iterate
    iterations = self.iteration
    iterations = iterations+1

    # keep max iterations up to date
    global max_iterations
    if iterations > max_iterations:
      max_iterations = iterations

    # generate the passwords hash / source  
    self.hash = hashlib.pbkdf2_hmac('sha256', masterpass, salt, iterations)
    
  def __repr__(self):
    # generate password plaintext with current settings
    if self.type == "hex":
      result = self.as_hex()

    # apply cropping if provided
    if self.crop_length:
      result = result[:self.crop_length]
    
    return result
  
  def as_hex(self):
    return self.hash.hex()

# generate default passwords
passwords = []
for i in range(5):
  passwords.append(Password())

print(passwords)