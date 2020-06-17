### import libraries ###
import hashlib
import os 
import base64

### set constants ###
SALT = b"PyPassSalt73871" # unique salt to counteract lookup tables
PASSWORD_TYPES = {"hex": 0, "Base64": 1, "Deciml": 3}
DEFAULT_TYPE = "hex"


HELP = """For a simple walkthrough to set up easily, type 'tutorial'
For more information on a specific command, type "help <command-name>"
help		Display help on commands
refresh		Refreshes a password to a new secure hash
rename		Changes the name attached to a password
custom		Sets a password to a custom string
settings	Changes the hash generation settings on a password
new		Creates a new password
import		Import settings from a file
masterpass	Change to a different master password
tutorial 	Display setup walkthrough"""

TUTORIAL = """Welcome to PyPassManager!
This is a simple tool to help safely manage a collection of secure passwords.
Security experts recommended that you use a different password for each account/site you use, so that if one is compromised, your other accounts are safe.
However, remembering even a single long random password is extremely challenging for most people
PyPassManager allows you to store a bunch of secure passwords, ezpz.

At initial launch, PyPassManager will generate three passwords for you. 
You can use these as-is and change your passwords to them, but theres some other things you can do to make this easier.
Say you wanted to change your email, twitter, and youtube passwords. Instead of having to remember which one is which, you can rename them within PyPass.
> rename Pass1 E-Mail
> rename Pass2 Twitter
> rename Pass3 YouTube

PyPassManager will automatically save your settings after each edit.
Now whenever you launch it, and provide the correct master password, the site name will be displayed alongside the password. 
Allowing you to easily copy&paste the right ones with no headaches.
Important to note is that PyPassManager can't automatically change your passwords for you, you'll have to do that part manually, PypassManager is just for storing a copy of them.

It's unrecommended, but if you need to store a specific predetermined password - e.g. a site wont let you change your pass, then you can do so using the custom command
> custom Twitter hunter2

If you want to go back to a random password, or if you need a new random password (e.g. the initial one randomly contained a bad word), use the refresh command
> refresh YouTube

If you need a new password, say you have 4 or more sites you use, use the new command (provide a name)
> new Scratch

Sometimes a site might have some restrictions on passwords which prevent you from using the generated ones, if this is the case you can change the generation settings.
By default, passwords are formed by rehashing your master password a number of times, then converting to Base64. If this is unsatisfactory, there's a few other options
Base64 - Will convert to a string of numbers, lower&uppercase letters, and + and /
Hexdec - Will instead convert into a string of numbers and the lowercase letters abcdef
Alphbt - Will convert to a string of just letters, upper&lowercase
Deciml - Will convert to a string of just numbers
Additionally, you can trim the password to a certain number of characters, just put the length as a number in the third part of the settings command
e.g.
> settings E-Mail Alphbt 16
> settings Scratch Deciml 1
> settings Scratch Base64
> settings YouTube Hexadecimal 50

Whenever you make any change it will be automatically saved to a file named "DO_NOT_DELETE_(passwords_XXX)" in the same directory as PyPassManager.py, where the XXX represent the first 3 letters of a hash of your master password.
this is also where the tool will look to find saved settings. You can also load alternative settings using the import command, followed by the filepath.
These setttings are only properly openable using the same master password. It's encrypted using by XORing with your master password.
The file doesn't directlty store any generated passwords, those are generated on the fly for added security, but it stores custom names and custom passwords, so it's recommended you keep the file to yourself.
If for whatever reason you forget your master password or want to change to a new one, you can use the masterpass command, which will automatically convert everything, note however that this will convert all your generated passwords into custom passwords.

Press Enter to continue..."""


### CLASSES ###
class Password:
  def __init__(self, iteration="max", type=DEFAULT_TYPE, crop=False, name="__default", file=False):

    if file:
      fil
    else:

    
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
### FUNCTIONS ###
def display():
  print(" --- PyPassManager --- ")
  for password in passwords:
    print(f"[{'!' if password.custom else password.iteration}] {password.name}: {password}")
  print("\ntype help for a list of commands")
  get_input()

def get_input():
  args = input("\n> ").split(" ")
  #if args: 
  #  args = args.sp
  #  print(args)
  command = args.pop(0)
  #else: return get_input()

  if command == "help":
    print(HELP)
    get_input()
  
  elif command == "tutorial":
    print(TUTORIAL)
    input("")
    display()

  elif command == "rename":
    if len(args) != 2:
      print("please provide 2 arguments")
    else:
      password = find_password(args[0])
      if password == "Not Found":
        print("no password found with name:", args[0])
      else:
        if find_password(args[1]) != "Not Found":
          print("password already exists with name:", args[1])
        else:
          password.name = args[1]
          return display()
    get_input()

  elif command == "refresh":
    if len(args) != 1:
      print("please provide 1 argument")
    else:
      password = find_password(args[0])
      if password == "Not Found":
        print("no password found with name:", args[0])
      else:
        password.refresh()
        display()
    get_input()

  elif command == "new":
    if len(args) > 3: 
      print("please provide fewer than 4 arguments")
      print("names cannot contain spaces")
      get_input()
    else:
      new_pass = Password()
      try:
        if len(args) > 0:
          new_pass.change_name(args[0])
          if len(args) > 1:
            new_pass.change_type(args[1])
            if len(args) > 2:
              new_pass.change_type(args[2])
      except UserWarning as e:
        print("Error creating password:")
        print(e)
        new_pass.delete()
        return get_input()
      passwords.append(new_pass)
      display()
  
  elif command == "custom":
    find_password(args[0])
    password = find_password(args[0])
    if password == "Not Found":
      print("no password found with name:", args[0])
      get_input()
    else:
      password.custom = args[1]
      display()

  elif command == "settings":
    if not (len(args) == 2 or len(args) == 3): 
      print("please provide 2 or 3 arguments")
      get_input()
    else:
      password = find_password(args[0])
      if password == "Not Found":
        print("Couldn't find password: ", args[0])
        return get_input()
      try:
        password.change_type(args[1])
        if len(args) == 3:
          password.change_crop(args[2])
      except UserWarning as e:
        print("Error changing settings:")
        print(e)
        return get_input()
      display()
  
  else:
    print("Unknown command:", command)
    get_input()

def find_password(name):
  result = list(filter(lambda x: x.name == name, passwords))
  if len(result) == 0:
    return "Not Found"
  else:
    return result[0]

### PROCEDURAL CODE ###
if __name__ == "__main__":
  # get master password
  masterpass = input("Enter your master password:\n")

  # convert into bytes so that it can be hashed
  masterpass = str.encode(masterpass)

  # turn plaintext password to hash, unreversable
  masterpass = hashlib.pbkdf2_hmac('sha512', masterpass, SALT, 10000)

  os.system('clear') # wipe the console
  print("LOADING with hash", masterpass.hex())

  # store how many refreshes used, to make sure the same password isnt used twice
  max_iterations = 0

  # generate default passwords
  passwords = []
  for i in range(3):
    passwords.append(Password())

  display()