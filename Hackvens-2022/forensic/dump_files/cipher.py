import hashlib, base64
"""
J'utilise ce programme pour stocker mes mots de passes de manière très sécurisé 
"""
password = input("Enter the password to complexify :")

key = "C31klétr3l0ngUe"



def xor(password, key):
    cipher = ""
    for i in range(0, len(password)):
        j = i % len(key)
        xor = ord(password[i]) ^ ord(key[j])
        cipher = cipher + chr(xor)
    return cipher

file = open("C:\\Users\\Jean\\Documents\\database.txt", "a").write(base64.b64encode(str.encode(xor(password,key))).decode("utf-8")+"\n")
