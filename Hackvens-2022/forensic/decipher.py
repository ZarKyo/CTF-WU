import hashlib, base64

password = "AZERTYUIO"
key = "C31klétr3l0ngUe"


def xor(password, key):
    cipher = ""
    for i in range(0, len(password)):
        j = i % len(key)
        xor = ord(password[i]) ^ ord(key[j])
        cipher = cipher + chr(xor)
    return cipher

a_file = open("./database.txt")

lines = a_file.readlines()
for line in lines:
    a = base64.b64decode(line).decode("utf-8")
    print(a+"\n")
    a = xor(a, key)
    print(a+"\n")