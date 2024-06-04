# -*- coding: utf-8 -*-
'''
Caleb Champion May 2024

CLI to find addresses, public keys, and private keys from a variety of private key options
Specifially the address type P2WPKH format
ONLY works with 24 word phrases
Expiremental ONLY, do not actually use for real money
'''

#packages
import pandas as pd #for opening bip39 wordlist in dataframe w/ 0 indexing
import hashlib #for sha256 hashes
import hmac #for HMAC hash of root_seed -> ext priv key
import binascii #for converting
from ecdsa import SigningKey, SECP256k1 #elliptic curve cryptography package

#bip 39 wordlist
bip39_words = pd.read_csv("english.txt")
bip39_words['index'] = range(len(bip39_words))

#exit all programs function
def exit_function():
    print("\nExiting the program")
    exit()
  
#enter 256 bits private key
def enter_256_bits():
    #to catch non integer values entered or a value not enetered
    while True:
        try:
            entropy_bits = str(input("\nType 0 to go back to main\nType 1 to go back\n\nDo not include spaces\nEnter 256 bits -> "))
            break
        except ValueError:
            print("\nValues can only be integers or no value entered")
    
    #if person wants to return to main or private key page
    if entropy_bits == '0':
        print("\nExiting and returning to main\n\n")
        return main()
    elif entropy_bits == '1':
        print("\nGoing back\n\n")
        return private_key_selection()
    
    #adding a passphrase, in PBKDF2 use 'None' to calculate without a phrase later
    passphrase = str(input("\nAdd a passphrase?\nType 'None' if you don't want a passphrase -> "))

    return str(entropy_bits), passphrase
            
#enter 24 word root_seed phrase
def enter_words():
    print("\nType 'Exit' any any time to exit mack to main\nType 'Back' at any time to go back to private key window\n")
    print("Enter 24 word root_seed phrase")
    words = []
    
    i = 0;

    while i < 24:
        word = input(f"Word #{i + 1} -> ").strip() #strip of accidental whitespace
        if not word:
            print("\nNo input detected, please enter a word")
            continue
        #if the result of a search for the word in bip39 is not empty, then add it to the word list
        if not bip39_words[bip39_words['words'] == word].empty:   
            words.append(word)
            i += 1
        elif not word.isalpha():
            print("\nOnly alphabetic characters allowed")
        elif word == "Exit":
            print("\nExiting and returning to main\n\n")
            return main()
        elif word == "Back":
            print("\nExiting and returning to private key window\n\n")
            return private_key_selection()
        else:
            print("\nWord is not in BIP39 wordlist, try again")
    
    
    #adding a passphrase, in PBKDF2 use 'None' to calculate without a phrase later
    passphrase = str(input("\nAdd a passphrase?\nType 'None' if you don't want a passphrase -> "))
                
    #returns wordlist
    return words, passphrase
    
#clears and updates all private keys to nothing
def clear_keys():
    entropy_256 = None
    words = None
    checksum = None
    ext_priv_key = None
    print("\nClearing all private keys...")
    
    return entropy_256, words, checksum, ext_priv_key

#calculate 24 root_seed phrase from 256 bits of entropy
def calc_words_from_bin(entropy_256):
    words = [0] * 24
  
    #checksum
    hexstr = "{0:0>4X}".format(int(entropy_256, 2))
    data = binascii.a2b_hex(hexstr) #hexadecimal to binary data
    hash_hex = hashlib.sha256(data).hexdigest() # SHA-256 hashing
    hash_bin = bin(int(hash_hex, 16))[2:] #convert the hexadecimal hash to binary

    #Ensure the binary string matches the original length
    #SHA-256 produces a 256-bit (32-byte) hash, so it needs to be trimmed to the length of entropy_256
    bin_digest = hash_bin.zfill(len(entropy_256))[:len(entropy_256)]
    
    #resulting checksum
    checksum = bin_digest[:8] #first 8 bits of hash
    
    #full 264 bits for 24 words
    entropy_264 = str(str(entropy_256) + checksum)
    
    #last 24 bits for 24th word
    checksum_bin = entropy_264[253:]
    
    #turn to int so its workable with % & //
    entropy_264 = int(entropy_264)
    
    #converting to words
    i = 24
    while i > 0:
        i -= 1
        word_bin = entropy_264 % 100000000000
        entropy_264 = entropy_264 // 100000000000
        
        #converting to decimal
        word_bin = str(word_bin)
        word_dec = int(word_bin, 2)
        
        word = str(bip39_words.loc[bip39_words.index[word_dec], "words"])
        words[i] = word
        
    #append checksum word
    checksum_dec = int(checksum_bin, 2)
    checksum_word = str(bip39_words.loc[bip39_words.index[checksum_dec], "words"])
    words[23] = checksum_word
    
    if TypeError: #pesky typeerror when already finished running, might actually fix later 
        None
    
    return words, checksum
   
#calculates the 256 bit binary and checksum from the 24 words 
def calc_bin_from_words(words):
    entropy_264 = str()
    
    #getting every words indice then finding binary from it
    for word in words:
        word_dec = int(bip39_words[bip39_words['words'] == word]['index'].values[0]) 
        word_bin = format(word_dec, '011b') #turn to 11 bit binary format
        word_bin = str(word_bin)
        entropy_264 += word_bin
    
    #finding 256 & checksum individually
    checksum = entropy_264[256:]
    entropy_256 = entropy_264[:256]
    
    return entropy_256, checksum

#PBKDF2 function used for root seed
def PBKDF2(words_bytes, salt_bytes, iterations, length):
    return hashlib.pbkdf2_hmac("sha512", words_bytes, salt_bytes, iterations, length).hex()

#calculates the root_seed
def find_seed(words, passphrase):
    iterations = 2048
    length = 64
    
    
    if passphrase == "None": #without passphrase
        salt = "mnemonic"
        words_string = " ".join(words)
        words_bytes = words_string.encode("utf-8")
        salt_bytes = salt.encode("utf-8")
        root_seed = PBKDF2(words_bytes, salt_bytes, iterations, length)
    else: #with passphrase
        salt = "mnemonic" + passphrase #add mnumonic to the salt
        words_string = " ".join(words)
        words_bytes = words_string.encode("utf-8")
        salt_bytes = salt.encode("utf-8")
        root_seed = PBKDF2(words_bytes, salt_bytes, iterations, length)
        
    return root_seed

#hmac-sha512 hash used for extended private key
def hmac_sha512(key, data):
    return hmac.new(key, data, hashlib.sha512).digest()

#finds extended private key w/ chain code
def ext_master_priv(root_seed):
    data = bytes.fromhex(root_seed)
    
    key = "426974636f696e2073656564" #"Bitcoin seed" in hex
    key = bytes.fromhex(key)
    
    #derive master private key
    ext_priv_key = hmac_sha512(key, data)

    return ext_priv_key.hex()    


#prints all results with all private key values already found
def print_priv_results(entropy_256, checksum, words, root_seed, ext_priv_key):
    print("\n\n\t\t\t\t\t\tPrinting Results...\n")
    print(f"Binary entropy: {entropy_256}\n")
    print(f"Checksum: {checksum}\n")
    print("Seed phrase:")
    i = 1
    for item in words:
        print(f"{i}.)", item)
        i += 1
    print(f"\nMaster root seed: {root_seed}")
    print(f"\nExtended private key: {ext_priv_key}")
    print(f"\nMaster private key: {ext_priv_key[:64]}")
    print(f"\nMaster chain code: {ext_priv_key[64:]}")
        
        
#selection for private key execution options
def private_key_selection():
    global entropy_256, checksum, words, ext_priv_key
    
    print("\n\t\t\t\t_______PRIVATE KEY WINDOW_______\n")
    print("To create or recover wallet, enter entropy in binary or enter seed phrase")
    print("1. Enter 256 bits of entropy")
    print("2. Enter 24 words root_seed phrase")
    print("3. To print all private keys")
    print("4. Enter to clear all private keys stored")
    print("5. To go back to main menu")
    print("6. To exit all programs\n")
    
    #error handling
    while True:
        try:
            selection_main = int(input("Selection number -> "))
            break
        except ValueError:
            print("\nMust enter an integer, try again\n")
    #selection choices & calculations with printing to follow
    if selection_main == 1:
        entropy_256, passphrase = enter_256_bits() #gathers binary
        words, checksum = calc_words_from_bin(entropy_256) #calculates words
        root_seed = find_seed(words, passphrase)
        ext_priv_key = ext_master_priv(root_seed)
        print_priv_results(entropy_256, checksum, words, root_seed, ext_priv_key) #prints results
    elif selection_main == 2:
        words, passphrase = enter_words() #gathers 24 word phrase
        entropy_256, checksum = calc_bin_from_words(words) #calculates binary
        root_seed = find_seed(words, passphrase)
        ext_priv_key = ext_master_priv(root_seed)
        print_priv_results(entropy_256, checksum, words, root_seed, ext_priv_key) #prints results
    elif selection_main == 3:
        try:    
            print_priv_results(entropy_256, checksum, words, root_seed, master_priv_key)
        except NameError: #none of the values are supplied
            print("\nYou must enter private keys first\n")
    elif selection_main == 4:
        entropy_256, checksum, words, ext_priv_key = clear_keys()
    elif selection_main == 5:
        return main()
    elif selection_main == 6:
        exit_function()
    else:
        print("\nEntry must be a number 1-5\n")
        private_key_selection()

#ecdsa cryptography
def ecdsa(priv_key):
    private_key_bytes = bytes.fromhex(priv_key)
    
    # Create a SigningKey object from the private key bytes
    private_key = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    
    # Get the corresponding VerifyingKey (which contains the public key)
    return private_key.get_verifying_key()

#calculate extended public key with ecdsa
def ext_master_pub(ext_priv_key):
    #calculate priv key from master_priv_key
    priv_key = ext_priv_key[:64]
    
    #eliptic curve cryptography
    public_key = ecdsa(priv_key)
    
    #points on graph
    public_key_point = public_key.pubkey.point
    x = public_key_point.x()
    y = public_key_point.y()
    
    #extended pub key = pub key + chain code
    public_key_hex = public_key.to_string().hex() #pub key
    
    #uncompressed is always prefixed w/ '04', compressed is '02' if even & '03' odd
    uncompress_ext_pub_key = "04" + public_key_hex + ext_priv_key[64:] #uncompressed version 
    
    if y % 2 == 0: #even
        compress_ext_pub_key = "02" + uncompress_ext_pub_key[2:66] #compressed version (just x coord needed)
    elif y % 2 != 0: #odd
        compress_ext_pub_key = "03" + uncompress_ext_pub_key[2:66]
        
    return uncompress_ext_pub_key, compress_ext_pub_key, x, y

#print the public key results
def public_key_results(uncompress_ext_pub_key, compress_ext_pub_key, x, y):
    print("\n\n\t\t\t\t\t\tPrinting Results...\n")
    print(f"Extended public key (uncompressed): {uncompress_ext_pub_key}")
    print(f"\nExtended public key (compressed): {compress_ext_pub_key}")
    print(f"\nCoordinates = x: {x}\n\t\t\t  y: {y}")

#public key selection window
def public_key_calculation():
    print("\n\t\t\t\t_______PUBLIC KEY WINDOW_______\n")
    if entropy_256 == '':
        print("You must enter private keys first")
        return private_key_selection()
    
    #calculating all results
    uncompress_ext_pub_key, compress_ext_pub_key, x, y = ext_master_pub(ext_priv_key)
    
    #printing all results
    public_key_results(uncompress_ext_pub_key, compress_ext_pub_key, x, y)
    
    
    
#main function with initial decisions
def main():
    while True:
        print("\n\t\t\t\t_______MAIN WINDOW________")
        print("Enter a private key first\n")
        print("1. Enter & view private keys")
        print("2. Enter to view public keys and addresses")
        print("3. Enter to view ALL private & public information")
        print("4. Exit program\n")
        main_selection = input("Selection number -> ")
        
        if main_selection == "1":
            private_key_selection()
        elif main_selection == "2":
            public_key_calculation()
        elif main_selection == "3":
            print("All information later")                ##################prints all information
        elif main_selection == "4":
            exit_function()
        else:
            print("\nSelection needs to be a 1, 2, or 3\n\n")
            main()
            
            
#runnimg main function
main()