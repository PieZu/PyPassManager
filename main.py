### import libraries ###
import os
import hashlib
import pickle

### set constants ###
from constants import *
### CLASSES ###
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
  with open(filename, mode='wb') as file:
    pickle.dump(passwords, file)
  
def generate_default():
  global passwords
  for i in range(3):
    passwords.append(Password())

def import_settings(filename):
  global passwords
  with open(filename, mode='rb') as file:
    passwords = pickle.load(file)
  import_passwords(passwords)
    
### COMMANDS ###
def find_command(name):
  for (cmd, help) in commands:
    if cmd.__name__ == name:
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
  input("")
  display()

def rename(args):
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
  masterpass = input("Enter your master password:\n")

  # convert into bytes so that it can be hashed
  masterpass = str.encode(masterpass)

  # turn plaintext password to hash, unreversable
  masterpass = hashlib.pbkdf2_hmac('sha512', masterpass, SALT, 10000)
  filename = f"{masterpass.hex()[:3]}_passwords.pypass"

  os.system('clear') # wipe the console
  print("LOADING with hash", masterpass.hex())

  # load password class
  from password_class import Password, find_password, passwords, set_masterpass, import_passwords
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