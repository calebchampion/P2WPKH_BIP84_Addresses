# -*- coding: utf-8 -*-

#Caleb Champion May 2024
#CLI to find addresses, public keys, and private keys from a variety of private key options
#Specifially the address type P2WPKH format
#ONLY works with 24 word phrases


#packages
import pandas as pd #for opening bip39 wordlist in dataframe w/ 0 indexing
import ast
import hashlib

#import bitcoinlib as btclib
#import bitcoin
#import ecdsa
#import binascii


#bip 39 wordlist
bip39_words = pd.read_csv("english.txt")


#exit all programs function
def exit_function():
    print("\nExiting the program")
    exit()

    
#enter 256 bits private key
def enter_256_bits():
    #to catch non integer values entered or a value not enetered
    while True:
        try:
            entropy_bits = int(input("\nType 0 to go back to main\nType 1 to go back\n\nEnter 256 bits -> "))
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
        
    #error handing
    maximum = 1
    minimum = 0
    for i in range(256):
        num = entropy_bits % 10
        entropy_bits / 10
        if num > 1:
            maximum = num
        if num < 0:
            minimum = num
                
    #checking if it has only 1s or 0s
    if maximum > 1 or minimum < 0:
        print("\nDigits in number must be 0 or 1")
        enter_256_bits()
    #checking if it has 256 digits of 1 or 0
    if len(str(entropy_bits)) != 256:
        print("\n256 bit private key must be 256 digits")
        enter_256_bits()
            
    #return the private key in binary format
    return entropy_bits
        
    
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
        

#enter hexidecimal priv key   
def enter_hex():
    print("\nType Exit at any time to exit function\nType Back to go back\n")
    hexadec = input("Enter 64 digit hexidecimal value -> ")
    
    #if not value is entered
    if not hexadec:
        print("\nNo input detected, please enter a word")
        return enter_hex()

    #if person wants to return main or go back
    elif hexadec.lower() == "exit": #lower for upper and lowecase exits typed
        print("\nExiting function and returning to main\n\n")
        return main()
    elif hexadec.lower() == "back": 
        print("\nGoing back\n")
        return private_key_selection()
    #error handling
    elif len(hexadec) != 64:
        print("\nHexidecimal must be 64 digits long")
        enter_hex()
    
    #returns hex format
    else:
        return hexadec
    
    
#clears and updates all private keys to nothing
def clear_priv_keys():
    master_binary_priv = None
    master_dec_priv= None
    master_hexadeci_priv = None
    words = None
    
    return master_binary_priv, master_hexadeci_priv, master_dec_priv, words

def calc_bin_from_dec(master_dec_priv):
    master_binary_priv = bin(master_dec_priv)[2:]
    return master_binary_priv

def calc_dec_from_bin(master_binary_priv):
    master_dec_priv = int(master_binary_priv, 2)
    return master_dec_priv

def calc_hex_from_dec(master_dec_priv):
    master_hexadeci_priv = hex(master_dec_priv)[2:]
    return master_hexadeci_priv

def calc_words_from_bin(master_binary_priv):
    words = []
    mnemo = Mnemonic('english')
    binary_data_bytes = int(master_binary_priv, 2).to_bytes((len(master_binary_priv) + 7) // 8, byteorder='big')
    words = mnemo.to_mnemonic(binary_data_bytes)
    return words

def calc_bin_from_words(words):
    mnemo = Mnemonic('english')
    entropy = mnemo.to_entropy(words)
    master_binary_priv = ''.join(f'{byte:08b}' for byte in entropy)
    return master_binary_priv

def calc_priv_key(master_binary_priv, master_dec_priv, master_hexadeci_priv, words):
    #has binary
    if master_binary_priv != None:
        master_dec_priv = calc_dec_from_bin(master_binary_priv)
        master_hexadeci_priv = calc_hex_from_dec(master_dec_priv)
        words = calc_words_from_bin(master_binary_priv)
    #has hexasdeci
    elif master_hexadeci_priv != None:
        master_dec_priv = ast.literal_eval(master_hexadeci_priv)
        master_binary_priv = calc_bin_from_dec(master_dec_priv)
        words = calc_words_from_bin(master_binary_priv)
    #has words
    elif words != None:
        master_binary_priv = calc_bin_from_words(words)
        master_dec_priv = calc_dec_from_bin(master_binary_priv)
        master_hexadeci_priv = calc_hex_from_dec(master_dec_priv)
    
    #returning all private key types
    return master_binary_priv, master_dec_priv, master_hexadeci_priv, words
    
    
#prints all results with all private key values already found
def print_results(master_binary_priv, master_hexadeci_priv, master_dec_priv, words):
    print("\n\n\t\t\tPrinting Resulting Keys\n")
    print(f"Binary format: {master_binary_priv}\n")
    print("Decimal fromat:", master_dec_priv)
    print("\nHexadecimal format:", master_hexadeci_priv)
    print("\nWords format:")
    for i in range(1, 24):
        print(f" {i}.", words[i])
        
        
        
#selection for private key execution options
def private_key_selection():
    print("\n\t\t\t\t_______PRIVATE KEY WINDOW_______\n")
    print("1. Enter 256 bits to get private key results")
    print("2. Enter 24 words to get private key results")
    print("3. Enter hexadecimal to get private key results")
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
        master_binary_priv = enter_256_bits()
        master_binary_priv, master_dec_priv, master_hexadeci_priv, words = calc_priv_key(master_binary_priv, None, None, None)
        print_results(master_binary_priv, master_hexadeci_priv, master_dec_priv, words)
    elif selection_main == 2:
        words = enter_words()
        master_binary_priv, master_dec_priv, master_hexadeci_priv, words = calc_priv_key(None, None, None, words)
        print_results(master_binary_priv, master_hexadeci_priv, master_dec_priv, words)
    elif selection_main == 3:
        master_hexadeci_priv = enter_hex()
        master_binary_priv, master_dec_priv, master_hexadeci_priv, words = calc_priv_key(None, None, master_hexadeci_priv, None)
        print_results(master_binary_priv, master_hexadeci_priv, master_dec_priv, words)
    elif selection_main == 4:
        master_binary_priv, master_hexadeci_priv, master_dec_priv, words = clear_priv_keys()
    elif selection_main == 5:
        return main()
    elif selection_main == 6:
        exit_function()
    else:
        print("\nEntry must be a number 1-6\n")
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
            
            
#runnign main function
main()