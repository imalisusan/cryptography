

{"ciphertext":" cf645e73660e397f5af88c672102326a 5ccaff72b1aa0093eaa04c9ecf434032 4da08de751fad9c5a2d91858f61d9469 f1 "}
                            IV                              CIPHERTEXT



                3fb88602c5c57ba38cc213affa1c754b2 0cdbed023cbbaf1ce863979d72ca5488 c9eb0817844abfeb65051b243e1e6c0
                        first exit                      second exit                         third exit



get flag
{"ciphertext":" b66ae7453c39b6040468eb573922e3f7    45f6bd7047f8436d83ea4d3fe773a4b5    b3198f25e4ce1f17ff5dff90edfe38c3 e1"}
                        IV

Given this IV I can know what are ALL the exits of the aes blocks, by just putting in input this IV and as plaintext 000000
so the xor dont do anything, I find out this

iv^0000
{"ciphertext":" 2684c4003397385de588120ed22c91cc    de74bc1296ff7c239302deb1cccf09e2    9c8e30974adfc3d22ea963055086b925 589930c3"}
                2684c4003397385de588120ed22c91cc    de74bc1296ff7c239302deb1cccf09e2    9c8e30974adfc3d22ea963055086b925
                crypto{0fb_15_5ymm37r1c4l_!!!11!}


OR, SECOND WAY:
import requests

url_base = 'http://aes.cryptohack.org/symmetry'

BLOCK_SIZE = 16

def hack():
  response = requests.get(url="%s/encrypt_flag/" % url_base).json()
  ciphertext = bytes.fromhex(response['ciphertext'])

  # Split the ciphertext into the IV and the actual ciphertext
  iv, ciphertext = ciphertext[:BLOCK_SIZE], ciphertext[BLOCK_SIZE:]

  # Encrypt the ciphertext (E_K(IV) ^ FLAG) which just will encrypt the supplied
  # IV as E_K(IV) and XOR it with the ciphertext and recover the flag. Abuses
  # the fact that encryption and decryption perform the same operation in OFB mode.
  response = requests.get(url="%s/encrypt/%s/%s" % (url_base, ciphertext.hex(), iv.hex())).json()
  plaintext = bytes.fromhex(response['ciphertext'])
  return plaintext.decode()
