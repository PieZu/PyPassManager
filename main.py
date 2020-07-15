### import libraries ###
import os
import hashlib
import pickle

### set constants ###
from constants import *

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

def save_settings():
  with open(filename, mode='wb') as file:
    pickle.dump(passwords, file)
  
def generate_default():
  global passwords
  for i in range(3):
    passwords.append(Password())

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
  from password_class import set_masterpass, Password, find_password, passwords
  set_masterpass(masterpass)

  # check for saved settings
  if os.path.exists(filename):
    try:
      print("Loading settings from", filename)
      with open(filename, mode='rb') as file:
        passwords.extend( pickle.load(file) )
    except Exception as e:
      print("Something went wrong, defaulting back.. Error:", e)
      # dont override settings
      filename = "NEW"+filename 
      generate_default()
  else:
    generate_default()
  display()