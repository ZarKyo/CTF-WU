# A strange dump

## Énoncé

> Vous avez récupéré un dump mémoire d'un ordinateur qui trainait lors d'une mission CSIRT. Celui-ci semble avoir réalisé des activités plus que douteuses. A vous de trouver des potentiels fichiers qui pourraient confirmer ou non vos soupçons.

## Solve

On a un dump mémoire à analyser, on va commencer par déterminer le profile avec Volatility2 :

```
./vol2 -f JEAN-PC-20220928-121426.raw imageinfo           
Volatility Foundation Volatility Framework 2.6
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_23418
                     AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/zarkyo/info/cyber/advens/forensic/JEAN-PC-20220928-121426.raw)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf800027f20a0L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0xfffff800027f3d00L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2022-09-28 12:14:29 UTC+0000
     Image local date and time : 2022-09-28 14:14:29 +0200
``` 

On remarque le fichier **confidential.7z** ouvert avec WinRAR :

```shell
./vol2 -f JEAN-PC-20220928-121426.raw --profile=Win7SP1x64 cmdline
Volatility Foundation Volatility Framework 2.6
************************************************************************
[...]
************************************************************************
WinRAR.exe pid:    180
Command line : "C:\Program Files\WinRAR\WinRAR.exe" "C:\Users\Jean\Desktop\Mes documents à moi\confidential.7z"
************************************************************************
cmd.exe pid:   2040
Command line : "cmd.exe" /s /k pushd "C:\Users\Jean\Desktop\Projets"
************************************************************************
conhost.exe pid:   1968
Command line : \??\C:\Windows\system32\conhost.exe
************************************************************************
mspaint.exe pid:   1944
Command line : "C:\Windows\system32\mspaint.exe" 
************************************************************************
[...]
```

On remarque l'éxecution d'un script de chiffrement **cipher.py** :

```shell
./vol2 -f JEAN-PC-20220928-121426.raw --profile=Win7SP1x64 cmdscan
Volatility Foundation Volatility Framework 2.6

**************************************************
CommandProcess: conhost.exe Pid: 1968
CommandHistory: 0x2344e0 Application: cmd.exe Flags: Allocated, Reset
CommandCount: 2 LastAdded: 1 LastDisplayed: 1
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x5c
Cmd #0 @ 0x2319e0: dir
Cmd #1 @ 0x2304a0: python cipher.py
Cmd #15 @ 0x1f0158: #
Cmd #16 @ 0x2337e0: #
**************************************************
CommandProcess: conhost.exe Pid: 404
CommandHistory: 0xe44e0 Application: DumpIt.exe Flags: Allocated
CommandCount: 0 LastAdded: -1 LastDisplayed: -1
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x5c
Cmd #15 @ 0xa0158: 
Cmd #16 @ 0xe37e0: 
```

On récupère le password utilisé pour chiffrer **AZERTYUIO** :

```shell
./vol2 -f JEAN-PC-20220928-121426.raw --profile=Win7SP1x64 consoles
Volatility Foundation Volatility Framework 2.6

**************************************************
ConsoleProcess: conhost.exe Pid: 1968
Console: 0xff3a6200 CommandHistorySize: 50
HistoryBufferCount: 2 HistoryBufferMax: 4
OriginalTitle: %SystemRoot%\system32\cmd.exe
Title: C:\Windows\system32\cmd.exe
AttachedProcess: cmd.exe Pid: 2040 Handle: 0x5c
----
CommandHistory: 0x23e430 Application: python.exe Flags: Reset
CommandCount: 1 LastAdded: 0 LastDisplayed: 0
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x0
Cmd #0 at 0x233040: AZERTYUIO
----
CommandHistory: 0x2344e0 Application: cmd.exe Flags: Allocated, Reset
CommandCount: 2 LastAdded: 1 LastDisplayed: 1
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x5c
Cmd #0 at 0x2319e0: dir
Cmd #1 at 0x2304a0: python cipher.py
----
Screen 0x210f70 X:80 Y:300
Dump:
                                                                                
C:\Users\Jean\Desktop\Projets>dir                                               
 Le volume dans le lecteur C n a pas de nom.                                    
 Le num?ro de s?rie du volume est 6074-0897                                     
                                                                                
 R?pertoire de C:\Users\Jean\Desktop\Projets                                    
                                                                                
19/09/2022  17:25    <REP>          .                                           
19/09/2022  17:25    <REP>          ..                                          
19/09/2022  17:09               539 cipher.py                                   
19/09/2022  17:26               163 Roadmap.txt                                 
               2 fichier(s)              702 octets                             
               2 R?p(s)  20?056?727?552 octets libres                           
                                                                                
C:\Users\Jean\Desktop\Projets>python cipher.py                                  
Enter the password to complexify :AZERTYUIO                                     
                                                                                
C:\Users\Jean\Desktop\Projets>                                                  
[...]                                                          
```

On va récupérer les fichiers qu'on a pu remarquer précédemment :

```shell
./vol2 -f JEAN-PC-20220928-121426.raw --profile=Win7SP1x64 filescan > file.txt
```

```shell
./vol2 -f JEAN-PC-20220928-121426.raw --profile=Win7SP1x64 dumpfiles --dump-dir=./ -Q 0x1ec64590
Volatility Foundation Volatility Framework 2.6
DataSectionObject 0x1ec64590   None   \Device\HarddiskVolume2\Users\Jean\Desktop\Mes documents à moi\confidential.7z
```

```shell
./vol2 -f JEAN-PC-20220928-121426.raw --profile=Win7SP1x64 dumpfiles --dump-dir=./ -Q 0x000000001ec71b30                  
Volatility Foundation Volatility Framework 2.6
DataSectionObject 0x1ec71b30   None   \Device\HarddiskVolume2\Users\Jean\Desktop\Projets\cipher.py
```

En parcourant le résultat du **filescan**, on remarque le fichier **database.txt** que l'on va aussi dump :

```shell
./vol2 -f JEAN-PC-20220928-121426.raw --profile=Win7SP1x64 dumpfiles --dump-dir=./ -Q 0x1ec789b0
Volatility Foundation Volatility Framework 2.6
DataSectionObject 0x1ec789b0   None   \Device\HarddiskVolume2\Users\Jean\Documents\database.txt
```

Le fichier **confidential.7z** est protégé par un password, on ne peut pas ouvrir les fichiers qu'il contient.

Si on s'intéresse au script python, on peut voir que celui-ci est utilisé pour chiffrer les password contenus dans le fichier **database.txt** :

```shell
cat cipher.py              
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
```

L'objectif va être de déchiffrer ces password et ainsi espérer trouver un password valide pour le **confidential.7z**.

On reprend le script initial, on le modifie un peu et on l'exécute :

```py
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
```

```shell
python decipher.py

[...]

Ma fonction de sécuritation de mot de passe fonctionne parfaitement ;) 

[...]

Password

[...]

Supermotdepassecompliqueavecdescaracteresspeci@x
[...]
```

**pass : Supermotdepassecompliqueavecdescaracteresspeci@x**

On décompresse l'archive avec le password :

```shell
7z e confidential.7z 

7-Zip [64] 17.04 : Copyright (c) 1999-2021 Igor Pavlov : 2017-08-28
p7zip Version 17.04 (locale=fr_FR.UTF-8,Utf16=on,HugeFiles=on,64 bits,16 CPUs x64)

Scanning the drive for archives:
1 file, 12288 bytes (12 KiB)

Extracting archive: confidential.7z

WARNINGS:
There are data after the end of archive

--
Path = confidential.7z
Type = 7z
WARNINGS:
There are data after the end of archive
Physical Size = 8369
Tail Size = 3919
Headers Size = 209
Method = LZMA2:24k 7zAES
Solid = +
Blocks = 1

    
Enter password (will not be echoed): Supermotdepassecompliqueavecdescaracteresspeci@x
Everything is Ok

Archives with Warnings: 1

Warnings: 1
Files: 2
Size:       18575
Compressed: 12288
```

```shell
cat note.txt    
Pseudo du contact :
HACKVENS{Vol1tility_4_th3_b35t}
Mot de passe admin du dom récupéré :
@Dm1n4lw45g3TStr@nGP@55w0rd
```

**Flag : HACKVENS{Vol1tility_4_th3_b35t}**