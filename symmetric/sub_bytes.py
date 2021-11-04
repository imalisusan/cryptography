import sys
import requests
import hashlib


def encrypt_padding(padding):
    r = requests.get('http://aes.cryptohack.org/ecb_oracle/encrypt/' + padding + '/')
    ciphertext = r.json()['ciphertext']
    return ciphertext # returns as hex
    
if __name__ == "__main__":

    # The 15 bytes to pad the plaintext initially (its just the hex for 'a...a' with 15 a's)
    initial_padding = "616161616161616161616161616161" 

    # The block of the ciphertext corresponding to the unpadded section.
    unpadded_ciphertext = encrypt_padding(initial_padding + "61")[32:64]

    # The bytes of the unpadded plaintext known so far
    known_bytes = ""

    for j in range(0,16):

        print("START ROUND %d\n" % j)

        # trim the prepend input, so the plaintext includes all the known bytes
        # The original prepend hex is 61....61 up until known bytes appear.

        padding = initial_padding
        if(j != 0):
            padding = initial_padding[:-(2*j)]

        print("prepend is %s \n" % (padding + known_bytes))

        ciphertext = ""

        if(padding == ""):
            ciphertext = unpadded_ciphertext
        else:
            ciphertext = encrypt_padding(padding)[0:32]

        print("ciphertext is %s\n" % ciphertext)

        # The last byte of this 16-byte ciphertext has only one unknown byte in the corresponding
        # plaintext. Namely, the last one.
    
        # Since it was encrypted with AES CBC, we may simply try encrypting all 255
        # possible plaintexts, and see when the corresponding ciphertext is produced. 

        found_byte = 0 

        for i in range(0, 255):

            last_byte = bytes([i]).hex()
    
            candidate_plaintext = padding + known_bytes + last_byte
    
            out = encrypt_padding(candidate_plaintext)
    
            if(out[:32] == ciphertext):

                found_byte = 1

                print("END ROUND %d \n" % j)
                print("The unknown byte is %s\n" % last_byte)

                known_bytes = known_bytes + last_byte
                break

        print("The known plaintext is: %s\n" % known_bytes)

        if not found_byte:
            print("Did not find the unknown byte... terminating\n")
            sys.exit(1)


