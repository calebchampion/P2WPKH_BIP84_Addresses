# -*- coding: utf-8 -*-

#Caleb Champion May 2024
#CLI to find addresses, public keys, and private keys from a variety of private key options
#Specifially the address type P2WPKH format
#ONLY works with 24 word phrases


#packages
import pandas as pd #for opening bip39 wordlist in dataframe w/ 0 indexing
import hashlib # for sha256 hashes
import binascii
import ecdsa

#import bitcoinlib as btclib
#import bitcoin
#import binascii

#bip 39 wordlist
bip39_words = pd.read_csv("english.txt")
bip39_words['index'] = range(len(bip39_words))

#PBKDF2_Rounds constant
PBKDF2_ROUNDS = 2048

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
    if entropy_bits == 0:
        print("\nExiting and returning to main\n\n")
        return main()
    elif entropy_bits == 1:
        print("\nGoing back\n\n")
        return private_key_selection()
    

    return str(entropy_bits)
            
#enter 24 word seed phrase
def enter_words():
    print("\nType 'Exit' any any time to exit mack to main\nType 'Back' at any time to go back to private key window\n")
    print("Enter 24 word seed phrase")
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
            
                
    #returns wordlist
    return words
    
#clears and updates all private keys to nothing
def clear_keys():
    entropy_256 = None
    words = None
    checksum = None
    
    return entropy_256, words, checksum

#calculate 24 seed phrase from 256 bits of entropy
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
    
    return words, checksum
    
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
    
#prints all results with all private key values already found
def print_priv_results(entropy_256, checksum, words):
    print("\n\n\t\t\t\t\t\tPrinting Results...\n")
    print(f"Binary entropy: {entropy_256}\n")
    print(f"Checksum: {checksum}\n")
    print("Seed phrase:")
    i = 1
    for item in words:
        print(f"{i}.)", item)
        i += 1
        
        
#selection for private key execution options
def private_key_selection():
    print("\n\t\t\t\t_______PRIVATE KEY WINDOW_______\n")
    print("To create or recover wallet, enter entropy in binary or enter seed phrase")
    print("1. Enter 256 bits of entropy")
    print("2. Enter 24 words seed phrase")
    print("3. Enter to clear all private keys stored")
    print("4. To go back to main menu")
    print("5. To exit all programs\n")
    
    #error handling
    while True:
        try:
            selection_main = int(input("Selection number -> "))
            break
        except ValueError:
            print("\nMust enter an integer, try again\n")
    #selection choices & calculations with printing to follow
    if selection_main == 1:
        entropy_256 = enter_256_bits() #gathers binary
        words, checksum = calc_words_from_bin(entropy_256) #calculates words
        print_priv_results(entropy_256, checksum, words) #prints results
    elif selection_main == 2:
        words = enter_words() #gathers 24 word phrase
        entropy_256, checksum = calc_bin_from_words(words) #calculates binary
        print_priv_results(entropy_256, checksum, words) #prints results
    elif selection_main == 3:
        entropy_256, checksum, words = clear_keys()
    elif selection_main == 4:
        return main()
    elif selection_main == 5:
        exit_function()
    else:
        print("\nEntry must be a number 1-5\n")
        private_key_selection()
        
        
#main function with initial decisions
def main():
    while True:
        print("\n\t\t\t\t_______MAIN WINDOW________\n")
        print("1. Enter functions calculating private keys")
        print("2. Enter functions calculating public keys and addresses")
        print("3. Exit program\n")
        main_selection = input("Selection number -> ")
        
        if main_selection == "1":
            private_key_selection()
        #elif main_selection == "2":
        #    public_key_selection()
        elif main_selection == "3":
            exit_function()
        else:
            print("\nSelection needs to be a 1, 2, or 3\n\n")
            main()
            
            
#runnimg main function
main()