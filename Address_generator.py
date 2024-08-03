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
bip39_words = pd.read_csv("BIP39_english.txt")
bip39_words['index'] = range(len(bip39_words))

n = SECP256k1.order #order of secp256k1 curve
  
#enter 256 bits private key with passphrase
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

#enter 24 word seed phrase with passphrase
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
    
    #make sure checksum for last word is correct
    check_words(words)
    
    #adding a passphrase, in PBKDF2 use 'None' to calculate without a phrase later
    passphrase = str(input("\nAdd a passphrase?\nType 'None' if you don't want a passphrase -> "))
                
    #returns wordlist
    return words, passphrase

#checking to see if words checksum is correct
def check_words(words): #local words being passed
    last_word = words[23]
    
    #checksum last word
    entropy_264 = str()
    for word in words:
        word_dec = int(bip39_words[bip39_words['words'] == word]['index'].values[0]) 
        word_bin = format(word_dec, '011b') #turn to 11 bit binary format
        word_bin = str(word_bin)
        entropy_264 += word_bin
    
    checksum_bin = entropy_264[253:]
    checksum_dec = int(checksum_bin, 2)
    
    checksum_word = str(bip39_words.loc[bip39_words.index[checksum_dec], "words"])

    
    #if word is not right vs. if word is right
    while last_word != checksum_word:
        print("\nChecksum for last word is not right")
        
        return enter_words()
    
    
#checksum calculator
def calc_checksum(entry):
    hexstr = "{0:0>4X}".format(int(entry, 2)) #formating
    hexstr = "0" + hexstr if len(hexstr) % 2 != 0 else hexstr #if its odd add a 0
    data = binascii.a2b_hex(hexstr) #hexadecimal to binary data
    hash_hex = sha256(data) # SHA-256 hashing
    hash_bin = bin(int(hash_hex, 16))[2:] #convert the hexadecimal hash to binary
    hash_bin = hash_bin[253:]
    
    return hash_bin
    
#enter hex private key with passphrase
def enter_hex():
    print("\nType 'Exit' any any time to exit mack to main\nType 'Back' at any time to go back to private key window\n")
    while True:
        try:
            hex_priv = str(input("Enter 64 characters of hex entropy -> "))
            #going back
            if hex_priv == "Back":
                print("\nExiting and returning to private key window\n\n")
                return private_key_selection()
            elif hex_priv == "Exit":
                print("\nExiting and returning to main\n\n")
                return main()
                
            #making sure it's 64 digits
            if len(hex_priv) != 64:
                print("\nHex string must be 64 characters long, try again\n\n")
            else:
                break
            
        except ValueError:
            print("\nSomething went wrong, try again")
            
    #changing to entropy_256 variable
    int_value = int(hex_priv, 16)
    binary_string = bin(int_value)[2:]
    entropy_256 = binary_string.zfill(256)
    
    #adding a passphrase, in PBKDF2 use 'None' to calculate without a phrase later
    passphrase = str(input("\nAdd a passphrase?\nType 'None' if you don't want a passphrase -> "))
    
    return entropy_256, passphrase, hex_priv

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
    hash_bin = calc_checksum(entropy_256)

    #ensure the binary string matches the original length
    #SHA-256 produces a 256-bit (32-byte) hash, so it needs to be trimmed to the length of entropy_256
    bin_digest = hash_bin.zfill(len(entropy_256))[:len(entropy_256)]
    
    #resulting checksum
    checksum = bin_digest[:8] #first 8 bits of hash
    
    #full 264 bits for 24 words
    entropy_264 = str(str(entropy_256) + checksum)
    
    #last 11 bits for 24th word
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

def calc_hex_from_bin():
    integer_value = int(entropy_256, 2)
    hex_priv = hex(integer_value)[2:].zfill(64)
    
    return hex_priv

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

#Wallet import format, Base58 encoded
def WIF_format(priv_key):
    private_key_bytes = bytes.fromhex(priv_key[:64])
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
    
    return WIF

#finds extended private key w/ chain code
def ext_master_priv(root_seed):
    data = bytes.fromhex(root_seed)
    
    key = b"Bitcoin seed" #key in byte form for hmac
    
    #derive master private key
    ext_priv_key = hmac_sha512(key, data).hex()
    
    
    #WIF formatting for private key
    WIF = WIF_format(ext_priv_key)
    
    return ext_priv_key, WIF

#prints all results with all private key values already found
def print_priv_results(hex_priv):
    print("\n\n\t\t\t\t\t\tPrinting Results...\n")
    print(f"Binary entropy: {entropy_256}\n")
    print(f"Checksum: {checksum}\n")
    print(f"Hex entropy: {hex_priv}\n")
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
    print("2. Enter 64 characters of hex entropy")
    print("3. Enter 24 words seed phrase")
    print("4. To print all private keys")
    print("5. Enter to clear all private keys stored")
    print("6. To go back to main menu")
    print("7. To exit all programs\n")
    
    #error handling
    while True:
        try:
            selection_main = int(input("Selection number -> "))
            break
        except ValueError:
            print("\nMust enter an integer, try again\n")
            
    #selection choices & calculations with printing to follow
    if selection_main == 1: #entered 256 bits
        entropy_256, passphrase = enter_256_bits() #gathers binary & passphrase
        hex_priv = calc_hex_from_bin() #calculates hex from binary
        words, checksum, = calc_words_from_bin(entropy_256) #calculates words
        root_seed = find_seed(words, passphrase) #calculates root seed
        ext_priv_key, WIF = ext_master_priv(root_seed) # calculates ext priv key
        master_chain_code = ext_priv_key[64:] #calculates chain code
        print_priv_results(hex_priv) #prints results
        
    elif selection_main == 2: #entered hex
        entropy_256, passphrase, hex_priv = enter_hex() #gathers hex & passphrase
        words, checksum = calc_words_from_bin(entropy_256) #calculates words
        root_seed = find_seed(words, passphrase) #calculates root seed
        ext_priv_key, WIF = ext_master_priv(root_seed) # calculates ext priv key
        master_chain_code = ext_priv_key[64:] #calculates chain code
        print_priv_results(hex_priv) #prints results
        
    elif selection_main == 3: #entered 24 words
        words, passphrase = enter_words() #gathers 24 word phrase & passphrase
        entropy_256, checksum = calc_bin_from_words(words) #calculates binary
        hex_priv = calc_hex_from_bin() #calculates hex from binary
        root_seed = find_seed(words, passphrase) #calculates root seed
        ext_priv_key, WIF = ext_master_priv(root_seed) #calculates ext priv key
        master_chain_code = ext_priv_key[64:] #calculates chain code
        print_priv_results(hex_priv) #prints results
        
    elif selection_main == 4:
        try: 
            print_priv_results() 
        except NameError: #none of the values are supplied
            print("\nYou must enter private keys first\n")
            
    elif selection_main == 5:
        entropy_256, checksum, words, ext_priv_key = clear_keys()
        
    elif selection_main == 6:
        return main()
    
    elif selection_main == 7:
        exit()
        
    else:
        print("\nEntry must be a number 1-5\n")
        private_key_selection()

#ecdsa cryptography
def ecdsa(priv_key_bytes):
    
    
    # Create a SigningKey object from the private key bytes
    private_key = SigningKey.from_string(priv_key_bytes, curve=SECP256k1)

    # Get the corresponding VerifyingKey (which contains the public key)
    return private_key.get_verifying_key()

#calculate extended public key with ecdsa
def ext_master_pub():
    #calculate priv key from master_priv_key
    priv_key = ext_priv_key[:64]
    
    #eliptic curve cryptography
    priv_key_bytes = bytes.fromhex(priv_key)
    public_key = ecdsa(priv_key_bytes)
    
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
    ripemd160 = ripemd160_algo(sha256_hash).hex()
    
    master_fingerprint = ripemd160[:8] #take first 4 bytes
    
    #go to results
    public_key_results(uncompress_pub_key, compress_pub_key, x, y)
    
#RIPEMD160 hash results
def ripemd160_algo(data):
    ripemd160 = hashlib.new("ripemd160")
    ripemd160.update(data)
    ripemd160_hash = ripemd160.digest()
    
    return ripemd160_hash

#bech32 hash from string ripmd160 to get address format
def bech32_encoding(pub_key_bytes):
    sha256_hash = hashlib.sha256(pub_key_bytes).digest()
    ripemd160_hash = ripemd160_algo(sha256_hash)
    version = 0  # Version for P2WPKH is 0
    witness_program = list(ripemd160_hash)
    data = [version] + bech32.convertbits(witness_program, 8, 5)
    bech32_address = bech32.bech32_encode("bc", data)
    return bech32_address

#child key derivation 
def CKD(priv_key, chain_code, index, hardened = False):
    if hardened:
        data = b"\x00" + bytes(priv_key) + index.to_bytes(4, "big")
    
    else:
        priv_key = bytes(priv_key)
        vk = ecdsa(priv_key)
        pub_key = vk.to_string("compressed")
        data = pub_key + index.to_bytes(4, byteorder = "big")

    hmac_result = hmac_sha512(data, chain_code)
    priv = int.from_bytes(hmac_result[:32], byteorder = "big")
    chain_code = hmac_result[32:]
    
    new_priv = (int.from_bytes(priv_key, "big") + priv) % n
    new_priv_bytes = new_priv.to_bytes(32, "big")
    
    return new_priv_bytes, chain_code

#child derivations
def derive_bip84_key(master_priv_key, master_chain_code, index, hardened):   
    #derive m/84'
    priv_key, chain_code = CKD(master_priv_key, master_chain_code, 84, hardened = True) #84' hardened = 84 + 2147483648
    #derive m/84'/0'
    priv_key, chain_code = CKD(priv_key, chain_code, 0, hardened = True) #0' hardened coin type == Bitcoin
    #derive m/84'/0'/0'
    priv_key, chain_code = CKD(priv_key, chain_code, 0, hardened = True) #0' hardened account = 0
    #derive m/84'/0'/0'/0
    priv_key, chain_code = CKD(priv_key, chain_code, 0) #0 receiving address = 0
    
    #calculate if hardened or not
    if not hardened:
        # Derive m/84'/0'/0'/0/index
        priv_key, chain_code = CKD(priv_key, chain_code, index) #index of address
    else:
        #derive m/84'/0'/0'/0/index'
        priv_key, chain_code = CKD(priv_key, chain_code, index, hardened = True) #index of hardened address
        
        
    return priv_key

#address calculation from index 0
def address_calculation():
    address_array = pd.DataFrame(columns=["index", "priv", "pub", "address"])
    
    print("\n\n\t\t\t\t\t\tPrinting Address information...\nUnhardened")
    
    master_priv_key = bytes.fromhex(ext_priv_key[:64])
    master_chain_code_bytes = bytes.fromhex(master_chain_code)
    
    for i in range(5):
        address_array.loc[i, "index"] = i
        print(f"Index: {i}")
        
        # PRIVATE KEY
        priv_key_bytes = derive_bip84_key(master_priv_key, master_chain_code_bytes, i, hardened = False)
        priv_hex = priv_key_bytes.hex()
        address_array.loc[i, "priv"] = priv_hex
        print(f"priv: {priv_hex}")
        wif = WIF_format(priv_hex)
        print(f"WIF: {wif}")
        
        # PUBLIC KEY
        public_key = ecdsa(priv_key_bytes)
        public_key_bytes = public_key.to_string("compressed")
        pub_key_hex = public_key_bytes.hex()
        
        print(f"pub: {pub_key_hex}")
        address_array.loc[i, "pub"] = pub_key_hex
        
        # ADDRESS
        address = bech32_encoding(public_key_bytes)
        address_array.loc[i, "address"] = address
        print(f"address: {address}\n")
        
    print("\nHardened Addresses: ")
    for i in range(2147483648, 2147483652): #hardened indexes
        address_array.loc[i, "index"] = i
        print(f"Index: {i}")
        
        #PRIVATE KEY
        priv_key_bytes = derive_bip84_key(master_priv_key, master_chain_code_bytes, i, hardened = True)
        priv_hex = priv_key_bytes.hex()
        address_array.loc[i, "priv"] = priv_hex
        print(f"priv: {priv_hex}")
        wif = WIF_format(priv_hex)
        print(f"WIF: {wif}")
        
        # PUBLIC KEY
        public_key = ecdsa(priv_key_bytes)
        public_key_bytes = public_key.to_string("compressed")
        pub_key_hex = public_key_bytes.hex()
        
        print(f"pub: {pub_key_hex}")
        address_array.loc[i, "pub"] = pub_key_hex
        
        # ADDRESS
        address = bech32_encoding(public_key_bytes)
        address_array.loc[i, "address"] = address
        print(f"address: {address}\n")
        
    

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
            try:
                public_key_calculation()
            except NameError:
                print("\nYou must enter private keys first")
        elif main_selection == "3":
            try:
                address_calculation()
            except NameError:
                print("\nYou must enter private & public keys first")
        elif main_selection == "4":
            exit()
        else:
            print("\nSelection needs to be a 1, 2, or 3\n\n")
            main()
            
#running main function
if __name__ == '__main__':
    main()