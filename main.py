### import libraries ###
import os
import hashlib
import pickle
import stringdist
from mnemonicode import mnformat
from crypto import encrypt, decrypt

### set constants ###
HELP = """For a simple walkthrough to set up easily, type 'tutorial'
For more information on a specific command, type "help <command-name>"
help		Display help on commands
refresh		Refreshes a password to a new secure hash
rename		Changes the name attached to a password
custom		Sets a password to a custom string
settings	Changes the hash generation settings on a password
suffix      Appends custom string at end of password
new	    	Creates a new password
import		Import settings from a file
setmaster	Change to a different master password
tutorial 	Display setup walkthrough""" # for >help

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
Additionally, you can trim the password to a certain number of characters, just put the length as a number in the third part of the settings command (0 = no trim)
e.g.
> settings E-Mail Alphbt 16
> settings Scratch Deciml 1
> settings Scratch Base64
> settings YouTube Hexadecimal 50

If these customisation options don't help, there's one more option, the suffix command
> suffix YouTube !#$012aA
this will add whatever text you provide (including spaces) to the end of the generated password. This suffix text is stored in the same way as a custom command; if you want to be as safe as possible keep its use to a minimum (only to bypass restrictions)
You can also set the suffix in the fourth option of the settings and/or new command
> settings Scratch Base64 0 !!0aA
> new Phone Deciml 4  (pin)

Whenever you make any change it will be automatically saved to a file named "DO_NOT_DELETE_(passwords_XXX)" in the same directory as PyPassManager.py, where the XXX represent the first 3 letters of a hash of your master password.
this is also where the tool will look to find saved settings. You can also load alternative settings using the import command, followed by the filepath.
These setttings are only properly openable using the same master password. It's encrypted using by XORing with your master password.
The file doesn't directlty store any generated passwords, those are generated on the fly for added security, but it stores custom names and custom passwords, so it's recommended you keep the file to yourself.
If for whatever reason you forget your master password or want to change to a new one, you can use the masterpass command, which will automatically convert everything, note however that this will convert all your generated passwords into custom passwords.

Press Enter to continue...""" # for >tutorial
INITIAL_SALT = b"PyPassSalt73871" # unique salt to counteract lookup tables
MAX_EDIT_DISTANCE = 2 # to account for typos in command names. restricted Damerau–Levenshtein distance

### CLASSES ###
from password_class import Password, find_password, passwords, set_masterpass, import_passwords

class Command:
  def __init__(self, name, code, help):
    self.name = name
    self.run = code
    self.help = help

### FUNCTIONS ###
def display():
  # display is called everytime the settings are changed. so first, we save
  save_settings()

  print(" --- PyPassManager --- ")
  for password in passwords:
    print(f"[{'!' if password.custom else password.iteration}] {password.name}: {password}")
  print("\ntype help for a list of commands")
  get_input()

def get_input():
  args = input("\n> ").split(" ")
  command = args.pop(0)

  function, _ = find_command(command)
  function(args)
  
def save_settings():
  raw_data = pickle.dumps(passwords)
  data = encrypt(raw_data, masterpass)
  with open(filename, mode='wb') as file:
    file.write(data)
  
def generate_default():
  global passwords
  for i in range(3):
    passwords.append(Password())

def import_settings(filename):
  global passwords
  with open(filename, mode='rb') as file:
    data = decrypt(file.read(), masterpass)
  passwords = pickle.loads(data)
  import_passwords(passwords) # set passwords variable in password_class.py module

### COMMANDS ###
def find_command(name):
  for (cmd, help) in commands:
    if stringdist.rdlevenshtein(cmd.__name__, name) <= MAX_EDIT_DISTANCE:
      return cmd, help
  else:
    print("Unknown command:", name)
    get_input()

def help(args):
  if len(args) == 0:
    # show general help
    print(HELP)
  else:
    # show help on specific command
    _, help = find_command(args[0])
    print(help)
  get_input()

def tutorial(args):
  print(TUTORIAL)
  input("") # wait for enter
  display()

def rename(args):
  if len(args) != 2:
    print("please provide 2 arguments")
  else:
    password = find_password(args[0])
    if password == "Not Found":
      print("no password found with name:", args[0])
    else:
      if find_password(args[1], error_correct=False) != "Not Found":
        print("password already exists with name:", args[1])
      else:
        password.name = args[1]
        return display()
  get_input()

def refresh(args):
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

def new(args):
  new_pass = Password()
  try:
    if len(args) > 0:
      new_pass.change_name(args.pop(0))
      if len(args) > 0:
        new_pass.change_type(args.pop(0))
        if len(args) > 0:
          new_pass.change_crop(args.pop(0))
          if len(args) > 0:
            new_pass.suffix = " ".join(args)
  except UserWarning as e:
    print("Error creating password:")
    print(e)
    new_pass.delete()
    return get_input()
  passwords.append(new_pass)
  display()

def custom(args):
  find_password(args[0])
  password = find_password(args[0])
  if password == "Not Found":
    print("no password found with name:", args[0])
    get_input()
  else:
    password.custom = " ".join(args[1:])
    display()

def settings(args):
  if len(args) < 2:
    print("please provide at least 2 arguments (name & type)")
    get_input()
  else:
    password = find_password(args[0])
    if password == "Not Found":
      print("Couldn't find password: ", args[0])
      return get_input()
    try:
      password.change_type(args[1])
      if len(args) > 2:
        password.change_crop(args[2])
        if len(args) > 3:
          password.suffix = " ".join(args[3:])
    except UserWarning as e:
      print("Error changing settings:")
      print(e)
      return get_input()
    display()

def load(args):
  if os.path.exists(filename):
    try:
      import_settings(args[0])
      display()
    except Exception as e:
      print("Encountered Error:", e)
      get_input()
  else:
    print("No file exists at", filename)
    get_input()

def suffix(args):
  name = args.pop(0)
  password = find_password(name)
  if password == "Not Found":
    print("no password found with name:", name)
    get_input()
  else:
    password.suffix = " ".join(args)
    display()

def setmaster(args):
  # save generated passwords as custom (as they generate differently with diff masterpass)
  for password in passwords:
    password.custom = password.__repr__()
  
  # generate new master hash
  global masterpass
  masterpass = str.encode(" ".join(args))
  masterpass = hashlib.pbkdf2_hmac('sha512', masterpass, SALT, 10000)
  set_masterpass(masterpass)

  # change save file to mash new hash
  global filename
  filename = f"{masterpass.hex()[:3]}_passwords.pypass"
  
  os.system('clear') # wipe the console
  print("LOADING with hash", masterpass.hex())
  display()

commands = [[help, "Prints a list of commands.\nUsage: help"],
 [tutorial, "Prints depth explanation on how to use this software.\nUsage: tutorial"], 
 [rename, "Changes the name associated with a password. Note that names cannot contain spaces.\nUsage: rename <current-name> <new-name>"], 
 [refresh, "'Refreshes' a password, regenerates a password using the same settings and a new hash.\nUsage: refresh <password-name>"], 
 [new, "Creates a new password, can specify any number of settings or leave blank for completely default.\nUsage: new [name] [type] [crop-length] [suffix ...]"],   
 [custom, "Sets a password text to any string. Undo with refresh command.\nUsage: custom <password-name> <password text ...>"], 
 [settings, "Set the settings used to generate a password.\nUsage: settings <password-name> <type> [crop-length] [suffix ...]"],   
 [load, "Load a .pypass save file generated with the same masterpass.\nUsage: load <path-to-file>"],   
 [suffix, "Append specified text to the end of a generated password.\nUsage: suffix <password-name> <suffix text ...>"],
 [setmaster, "Change master password (the one you enter at program launch) and load all saved settings into it. (not recommended). Usage: setmaster <new master password ...>"]]

### PROCEDURAL CODE ###
if __name__ == "__main__":
  # get master password
  print("WARNING: Make sure this is unguessable! Recommend a bunch of random words, e.g.:", mnformat(os.urandom(8), word_separator=" ", group_separator=" "))
  masterpass = input("Enter your master password:\n")

  # convert into bytes so that it can be hashed
  masterpass = str.encode(masterpass)

  # turn plaintext password to hash, unreversable
  masterpass = hashlib.pbkdf2_hmac('sha512', masterpass, INITIAL_SALT, 10000)
  filename = f"{masterpass.hex()[:3]}_passwords.pypass"

  os.system('clear') # wipe the console
  print("LOADING with hash", masterpass.hex())

  # load password class
  set_masterpass(masterpass)

  # check for saved settings
  if os.path.exists(filename):
    print("Loading settings from", filename)
    try:
      import_settings(filename)
    except Exception as e:
      print("Something went wrong, defaulting back.. Error:", e)
      # dont override settings
      filename = "NEW"+filename 
      generate_default()
  else:
    print("No settings file detected, defaulting...")
    generate_default()

  display()