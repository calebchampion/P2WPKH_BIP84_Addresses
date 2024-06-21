# Address calculator
## Understanding bitcoin addresses in the P2WPKH form
1. Creates or uses **BIP39 seed phrase** from 256 bit entropy, or other way around.
2. Calculates 64 byte **root seed** with 2048 iterations of PBKDF2-HMAC-SHA512 using seed phrase and salt for (**passphrase**).
3. Uses HMAC-SHA512 to hash the root seed to calulate the 64 byte **parent extended private key(master extended private key)** by adding the first 32 bytes **master private key** and the last 32 bytes **master chain code** from the HMAC-SHA512 hash to be used for the BIP32 Hierarchical Deterministic children keys later.  The chain code will be used to construct the child keys.
4. Use Base58 encoding to convert **master private key** -> **WIF** #this only encodes it in an easy format, can be easily undone.
5. Used the **master private key** and ECDSA to solve for the compressed (& uncompressed) **master public key**, then adding that with the chain code to calculate the **parent extended public key(master extended public key)**.
6. Creates **master fingerprint** by hashing the compressed public key with sha256 and ripemd160 to find first 4 bytes.  So sha256(ripemd160(compress pub key))[first 4 bytes].
7. Create **child private keys** in "normal" format for non hardened addresses.  Then calculate the private keys for hardened indexes afterwards.  Normal keys follows HMAC-SHA512((master public key + index), master chain code) = "result".  Then (master private key + "result"[first 32 bytes]) % order of SECP256k1 curve = **child private key**.  Hardened simply replaces the HMAC-SH512(master public key + index) with HMAC-SH512(master private key + index).
8. Calculate the **child public keys** by using ECDSA on the child private keys and solving for **compressed public key** like in step 5.
9. Last, calculate the addresses of all keys by hashing the child public key with ripemd160(bech32("bc", child public key)) to get it in (bc1q) **P2WPKH address** form.

### Directions
Need to download "english" file as it is the bip39 wordlist used for conversion.  Just change "english" to the file path and name.

Some packages are already included in pip if download is recent enough.

    $ pip install pandas as pd
    $ pip install hashlib
    $ pip install hmac
    $ pip install binascii
    $ pip install ecdsa
    $ pip install base58
    $ pip install bech32

#### Sources used to understand everything
"Mastering Bitcoin: Programming the Open Blockchain" Andreas Antonopoulos

"Programming Bitcoin" Jimmy Song, https://github.com/jimmysong/programmingbitcoin

https://learn.saylor.org/  "CS120 Bitcoin for Developers"

https://cypherpunks-core.github.io/bitcoinbook/

https://bip32jp.github.io/english/

https://iancoleman.io/bip39/

https://bitaps.com/bip32

https://bitcoiner.guide/seed/

https://privatekeys.pw/calc

https://developer.bitcoin.org/devguide/index.html

https://armantheparman.com/

https://learnmeabitcoin.com/

https://www.youtube.com/@specter163/videos  "Build your own Bitcoin hardware wallet videos"
