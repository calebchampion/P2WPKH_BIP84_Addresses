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
import ecdsa #elliptic curve cryptography package

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
    print("\nClearing all private keys...")
    
    return entropy_256, words, checksum

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

#calculates the root_seed
def PBKDF2(words, passphrase):
    iterations = 2048
    length = 64
    
    
    if passphrase == "None": #without passphrase
        salt = "mnemonic"
        words_string = " ".join(words)
        words_bytes = words_string.encode("utf-8")
        salt_bytes = salt.encode("utf-8")
        root_seed = hashlib.pbkdf2_hmac("sha512", words_bytes, salt_bytes, iterations, length).hex()
    else: #with passphrase
        salt = "mnemonic" + passphrase #add mnumonic to the salt
        words_string = " ".join(words)
        words_bytes = words_string.encode("utf-8")
        salt_bytes = salt.encode("utf-8")
        root_seed = hashlib.pbkdf2_hmac("sha512", words_bytes, salt_bytes, iterations, length).hex()
        
    return root_seed
    
#calculates the extended private key by hashing HMAC with the root_seed and message "Bitcoin seed"
def HMAC_master_priv(root_seed):
    message = "Bitcoin seed"
    key = root_seed
    key_bytes = key.encode('utf-8')
    message_bytes = message.encode('utf-8')
    hmac_obj = hmac.new(key_bytes, message_bytes, hashlib.sha512)
    ext_priv_key = hmac_obj.hexdigest()
    
    return ext_priv_key
    
#prints all results with all private key values already found
def print_priv_results(entropy_256, checksum, words, root_seed, ext_priv_key):
    print("\n\n\t\t\t\t\t\tPrinting Results...\n")
    print(f"Binary entropy: {entropy_256}\n")
    print(f"Checksum: {checksum}\n")
    print("root_seed phrase:")
    i = 1
    for item in words:
        print(f"{i}.)", item)
        i += 1
    print(f"\nMaster root_seed: {root_seed}")
    print(f"\nExtended Private Key(master): {ext_priv_key}")
    print(f"\nPrivate Key: {ext_priv_key[:64]}")
    print(f"\nChain Code: {ext_priv_key[64:]}")
        
        
#selection for private key execution options
def private_key_selection():
    global entropy_256, checksum, words
    
    print("\n\t\t\t\t_______PRIVATE KEY WINDOW_______\n")
    print("To create or recover wallet, enter entropy in binary or enter root_seed phrase")
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
        root_seed = PBKDF2(words, passphrase)
        ext_priv_key = HMAC_master_priv(root_seed)
        print_priv_results(entropy_256, checksum, words, root_seed, ext_priv_key) #prints results
    elif selection_main == 2:
        words, passphrase = enter_words() #gathers 24 word phrase
        entropy_256, checksum = calc_bin_from_words(words) #calculates binary
        root_seed = PBKDF2(words, passphrase)
        ext_priv_key = HMAC_master_priv(root_seed)
        print_priv_results(entropy_256, checksum, words, root_seed, ext_priv_key) #prints results
    elif selection_main == 3:
        try:    
            print_priv_results(entropy_256, checksum, words, root_seed, ext_priv_key)
        except NameError: #none of the values are supplied
            print("\nYou must enter private keys first\n")
    elif selection_main == 4:
        entropy_256, checksum, words = clear_keys()
    elif selection_main == 5:
        return main()
    elif selection_main == 6:
        exit_function()
    else:
        print("\nEntry must be a number 1-5\n")
        private_key_selection()
        
def public_key_selection():
    print("\n\t\t\t\t_______PUBLIC KEY WINDOW_______\n")
    if entropy_256 == '':
        print("You must enter private keys first")
        return private_key_selection()
        
#main function with initial decisions
def main():
    while True:
        print("\n\t\t\t\t_______MAIN WINDOW________")
        print("Enter a private key first\n")
        print("1. Enter & view private keys")
        print("2. Enter to view public keys and addresses")
        print("3. Exit program\n")
        main_selection = input("Selection number -> ")
        
        if main_selection == "1":
            private_key_selection()
        elif main_selection == "2":
            public_key_selection()
        elif main_selection == "3":
            exit_function()
        else:
            print("\nSelection needs to be a 1, 2, or 3\n\n")
            main()
            
            
#runnimg main function
main()