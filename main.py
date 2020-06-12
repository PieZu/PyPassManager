import hashlib
import os 

# get master password
masterpass = input("Enter your master password:\n")
os.system('clear') # wipe the console
# convert into bytes so that it can be hashed
masterpass = str.encode(masterpass)

# turn plaintext password to hash, unreversable
salt = b"PyPassSalt73871" # unique salt to counteract lookup tables
masterpass = hashlib.pbkdf2_hmac('sha512', masterpass, salt, 10000)

# store how many refreshes used, to make sure the same password isnt used twice
max_iterations = 0

class Password:
  def __init__(self, iteration="max", type="hex", crop=False, name="__default"):

    # by default the password will start off with the next iteration after the max (.refresh will bring it up by 1). For some reason setting this directly in the parameter definition doesn't work when you change max_iterations dynamically. Weird.
    if iteration == "max": 
      iteration = max_iterations
    if name == "__default": # same thing with name wont work directly in the parameter
      name = "Pass"+str(iteration+1)

    # store settings
    self.type = type
    self.crop_length = crop
    self.iteration = iteration
    self.name = name

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

    # store updated iteration
    self.iteration = iterations
    
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
for i in range(3):
  passwords.append(Password())

def display():
  print(" --- PyPassManager --- ")
  for password in passwords:
    print(f"[{password.iteration}] {password.name}: {password}")
  print("\ntype help for a list of commands")
  get_input()

def get_input():
  command = input("\n> ")
  if command == "help":
    print("""For a simple walkthrough to set up easily, type 'tutorial'
For more information on a specific command, type "help <command-name>"
help		Display help on commands
refresh		Refreshes a password to a new secure hash
rename		Changes the name attached to a password
custom		Sets a password to a custom string
settings	Changes the hash generation settings on a password
new		Creates a new password
import		Import settings from a file
masterpass	Change to a different master password
tutorial 	Display setup walkthrough""")
    get_input()
  elif command == "tutorial":
    print("""Welcome to PyPassManager!
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

Press any key to continue...""")
    input("")
    display()
  else:
    print("Unknown command: ", command)
    get_input()

display()