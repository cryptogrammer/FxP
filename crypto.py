import rsa

(pub_key, priv_key) = rsa.newkeys(512)
message = "TEST STRING"
encryptedMessage = rsa.encrypt(message, pub_key)
print(rsa.decrypt(encryptedMessage, priv_key))
