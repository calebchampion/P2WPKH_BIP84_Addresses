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
import base58 #for encoding addresses & WIF
import bech32 #for encoding in bech32 for addresses

#bip 39 wordlist
bip39_words = pd.read_csv("english.txt")
bip39_words['index'] = range(len(bip39_words))

#for ecdsa tracking
j = 0

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

#sha256 hash function used for multiple things
def sha256(data):
    return hashlib.sha256(data).hexdigest()

#calculate 24 root_seed phrase from 256 bits of entropy
def calc_words_from_bin(entropy_256):
    words = [0] * 24
  
    #checksum
    hexstr = "{0:0>4X}".format(int(entropy_256, 2)) #formating
    hexstr = "0" + hexstr if len(hexstr) % 2 != 0 else hexstr #if its odd add a 0
    data = binascii.a2b_hex(hexstr) #hexadecimal to binary data
    hash_hex = sha256(data) # SHA-256 hashing
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

#base58 encoding for address & WIF
def base58_encode(data):
    return base58.b58encode(data)

#finds extended private key w/ chain code
def ext_master_priv(root_seed):
    data = bytes.fromhex(root_seed)
    
    key = "426974636f696e2073656564" #"Bitcoin seed" in hex version as salt
    key = bytes.fromhex(key)
    
    #derive master private key
    ext_priv_key = hmac_sha512(key, data).hex()
    
    
    #WIF formatting for private key
    private_key_bytes = bytes.fromhex(ext_priv_key[:64])
    prefix = b'\x80' #mainet == "80"
    extended_key = prefix + private_key_bytes
    extended_key += b'\x01' #compression == True

    #checksum
    sha256_1 = hashlib.sha256(extended_key).digest()
    sha256_2 = hashlib.sha256(sha256_1).digest()
    checksum = sha256_2[:4] 

    #calculating WIF w/ Base58
    final_key = extended_key + checksum
    WIF = base58_encode(final_key).decode('utf-8')
    
    return ext_priv_key, WIF

#prints all results with all private key values already found
def print_priv_results():
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
    print(f"\nWIF: {WIF}")
    print(f"\nMaster private key: {ext_priv_key[:64]}")
    print(f"\nMaster chain code: {master_chain_code}")
        
        
#selection for private key execution options
def private_key_selection():
    global entropy_256, checksum, words, ext_priv_key, master_chain_code, root_seed, WIF
    
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
        root_seed = find_seed(words, passphrase) #calculates root seed
        ext_priv_key, WIF = ext_master_priv(root_seed) # calculates ext priv key
        master_chain_code = ext_priv_key[64:] #calculates chain code
        print_priv_results() #prints results
    elif selection_main == 2:
        words, passphrase = enter_words() #gathers 24 word phrase
        entropy_256, checksum = calc_bin_from_words(words) #calculates binary
        root_seed = find_seed(words, passphrase) #calculates root seed
        ext_priv_key, WIF = ext_master_priv(root_seed) #calculates ext priv key
        master_chain_code = ext_priv_key[64:] #calculates chain code
        print_priv_results() #prints results
    elif selection_main == 3:
        try: 
            print_priv_results() 
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
    
    
    global j
    if j == 0: # on only the first run
        #get order of curve
        global n
        curve = private_key.curve
        n = curve.order
    
    j = j + 1
    
    # Get the corresponding VerifyingKey (which contains the public key)
    return private_key.get_verifying_key()

#calculate extended public key with ecdsa
def ext_master_pub():
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
    uncompress_pub_key = "04" + public_key_hex #uncompressed version 
    
    if y % 2 == 0: #even
        compress_pub_key = "02" + uncompress_pub_key[2:66] #compressed version (just x coord needed)
    elif y % 2 != 0: #odd
        compress_pub_key = "03" + uncompress_pub_key[2:66]
        
    return uncompress_pub_key, compress_pub_key, x, y

#print the public key results
def public_key_results(uncompress_pub_key, compress_pub_key, x, y):
    print("\n\n\t\t\t\t\t\tPrinting Results...\n")
    print(f"Master fingerprint: {master_fingerprint}")
    print(f"\nMaster public key (uncompressed): {uncompress_pub_key}")
    print(f"\nMaster public key (compressed): {compress_pub_key}")
    print(f"\nExtended public key: {ext_public_key}")
    print(f"\nCoordinates = x: {x}\n\t\t\t  y: {y}")

#public key selection window
def public_key_calculation():
    global ext_public_key, master_chain_code, master_fingerprint
    
    print("\n\t\t\t\t_______PUBLIC KEY WINDOW_______\n")
    
    #calculating all results
    uncompress_pub_key, compress_pub_key, x, y = ext_master_pub() #ecdsa
    ext_public_key = compress_pub_key + master_chain_code #ext pub key
    
    #master fingerprint  sha256 hash pub, then ripemd160
    compress_pub_key_bytes = bytes.fromhex(compress_pub_key)
    sha256_hash = hashlib.sha256(compress_pub_key_bytes).digest()
    ripemd160 = ripemd160_algo(sha256_hash)
    
    master_fingerprint = ripemd160[:8] #take first 4 bytes
    
    #go to results
    public_key_results(uncompress_pub_key, compress_pub_key, x, y)
    
#RIPEMD160 hash results
def ripemd160_algo(data):
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(data)
    ripemd160_hash = ripemd160.digest()
    
    return ripemd160_hash.hex()

#bech32 hash from string ripmd160 to get address format
def bech32_encoding(ripemd160_hash):
    ripemd160_hash = bytes.fromhex(ripemd160_hash)
    version = 0  # Version for P2WPKH is 0
    witness_program = list(ripemd160_hash)
    data = [version] + bech32.convertbits(witness_program, 8, 5)
    bech32_address = bech32.bech32_encode("bc", data)
    
    return bech32_address
    
#address calculation as hardened version starting from index 0
#this calculates addresses and keys to children in an unsafe manner
#calculates address from private key, so would be hardened if large enough index is selected

def address_calculation():
    global address_array
    
    #calculates and prints zpriv, zpub, & address
    print("\n\n\t\t\t\t\t\tPrinting Address information...\n")
    
    #create address array of priv, pub, and addresses
    address_array = pd.DataFrame({"index": [], "priv": [], "pub": [], "address": []})
    
    i = 0
    while i < 6:
        address_array.loc[i, "index"] = i
        
        #PRIVATE KEY
        data = ext_priv_key[:32] + str(i) #data (mast priv key + index)
        data = data.encode("utf-8") #encode in bytes
        key = master_chain_code.encode("utf-8") #incode in bytes
        hmac_result = hmac_sha512(data, key)[:32] #hmac(master priv + index, master chain code)
        hmac_result = int.from_bytes(hmac_result, byteorder='big') #in int format
        master_priv = int(ext_priv_key[:64], 16) #in int format
        priv = (master_priv + hmac_result) % n #(master priv + hmac_result) % n(order of curve)
        priv = str(hex(priv)[2:])
        address_array.loc[i, "priv"] = priv
        
        
        #PUBLIC KEY
        public_key = ecdsa(priv)
        public_key_hex = public_key.to_string().hex() #pub key
        
        public_key_point = public_key.pubkey.point #points on graph
        y = public_key_point.y()
        
        #uncompressed is always prefixed w/ '04', compressed is '02' if even & '03' odd
        uncompress_pub_key = "04" + public_key_hex #uncompressed version 
        
        if y % 2 == 0: #even
            pub = "02" + uncompress_pub_key[2:66] #compressed version (just x cord needed)
        elif y % 2 != 0: #odd
            pub = "03" + uncompress_pub_key[2:66]
            
        
        address_array.loc[i, "pub"] = str(pub)
        
        
        #ADDRESS
        pub = pub.encode("utf-8")
        ripemd160_hash = ripemd160_algo(pub)
        address = bech32_encoding(ripemd160_hash)
        address_array.loc[i, "address"] = str(address)
        
        #printing results
        print(f"{i}.) priv: {priv}, pub: {pub}, address: {address}\n")
        
        i = i + 1

#main function with initial decisions
def main():
    while True:
        print("\n\t\t\t\t_______MAIN WINDOW________")
        print("Enter a private key first\n")
        print("1. Enter & view private keys")
        print("2. Enter to view public keys")
        print("3. Enter to view child address information")
        print("4. Exit program\n")
        main_selection = input("Selection number -> ")
        
        if main_selection == "1":
            try: 
                private_key_selection()
            except NameError:
                print("\nYou must enter private keys first")
        elif main_selection == "2":
            public_key_calculation()
        elif main_selection == "3":
            try:
                address_calculation()
            except NameError:
                print("\nYou must enter private & public keys first")
        elif main_selection == "4":
            exit_function()
        else:
            print("\nSelection needs to be a 1, 2, or 3\n\n")
            main()
            
#runnimg main function
main()