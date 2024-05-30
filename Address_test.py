# -*- coding: utf-8 -*-

#Caleb Champion May 2024
#CLI to find addresses, public keys, and private keys from a variety of private key options
#Specifially the address type P2WPKH format
#ONLY works with 24 word phrases


#packages
import pandas as pd #for opening bip39 wordlist in dataframe w/ 0 indexing
import ast
from mnemonic import Mnemonic
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
    entropy_bits = bin(entropy_bits)[2:]
    if not all(char in '01' for char in entropy_bits):
        print("\nDigits in number must be 0 or 1")
        return enter_256_bits()
                
    #checking if it has 256 digits
    if len(entropy_bits) == 256:
        return entropy_bits
        
    else:
        print("\nEntropy must be 256 digits")
        enter_256_bits()
            
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
    
    return entropy_256, words

#calculate 24 seed phrase from 256 bits of entropy
def calc_words_from_bin(entropy_256):
    words = []
    mnemo = Mnemonic('english')
    binary_data_bytes = int(entropy_256, 2).to_bytes((len(entropy_256) + 7) // 8, byteorder='big')
    words = mnemo.to_mnemonic(binary_data_bytes)
    return words

#calculates entropy from 24 word seed phrase
def calc_bin_from_words(words):
    mnemo = Mnemonic('english')
    entropy = mnemo.to_entropy(words)
    entropy_256 = ''.join(f'{byte:08b}' for byte in entropy)
    return entropy_256
    
    
#prints all results with all private key values already found
def print_results(entropy_256, words):
    print("\n\n\t\t\t\t\t\tPrinting Results...\n")
    print(f"Binary entropy: {entropy_256}\n")
    print("Seed phrase:")
    for i in range(1, 24):
        print(f" {i}.", words[i])
        
        
        
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
        words = calc_words_from_bin(entropy_256) #calculates words
        print_results(entropy_256, words) #prints results
    elif selection_main == 2:
        words = enter_words() #gathers 24 word phrase
        entropy_256 = calc_bin_from_words(words) #calculates binary
        print_results(entropy_256, words) #prints results
    elif selection_main == 3:
        entropy_256, words = clear_keys()
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
            
            
#runnign main function
main()