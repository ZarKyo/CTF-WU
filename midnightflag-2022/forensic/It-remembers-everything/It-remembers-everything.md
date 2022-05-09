# It-remembers-everything

Catégorie : Forensics

## It-remembers-everything 1/3

Difficulté : facile

### Enoncé

> Lors d'un raid sur un camp ennemi, nous avons tout juste eu le temps de dump la mémoire d'un ordinateur avant que celle-ci ne soit effacée. Malheureusement, nous n'avons aucune information sur la manière dont la machine était utilisée. Retrouvez le nom de l'utilisateur ainsi que celui de la machine.
>
> Format : MCTF{nomutilisateur:nommachine}

```shell
└─$ ./vol2 -f chall.raw imageinfo

Volatility Foundation Volatility Framework 2.6
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_23418
                     AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/zarkyo/midnight/forensic/chall.raw)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf80002803070L
          Number of Processors : 1
     Image Type (Service Pack) : 0
                KPCR for CPU 0 : 0xfffff80002804d00L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2022-04-09 12:18:42 UTC+0000
     Image local date and time : 2022-04-09 14:18:42 +0200
                                                                                                                                      

└─$ ./vol2 -f chall.raw --profile=Win7SP1x64 hivelist
Volatility Foundation Volatility Framework 2.6
Virtual            Physical           Name
------------------ ------------------ ----
0xfffff8a001c07010 0x0000000077ec2010 \??\C:\System Volume Information\Syscache.hve
0xfffff8a005da0010 0x000000002a739010 \SystemRoot\System32\Config\SECURITY
0xfffff8a005df9420 0x000000002a999420 \SystemRoot\System32\Config\SAM
0xfffff8a00000f010 0x000000002d415010 [no name]
0xfffff8a000024010 0x000000002d3e0010 \REGISTRY\MACHINE\SYSTEM
0xfffff8a00004e010 0x000000002d3ca010 \REGISTRY\MACHINE\HARDWARE
0xfffff8a0009f2010 0x000000002bced010 \SystemRoot\System32\Config\DEFAULT
0xfffff8a000ac8420 0x000000004fe10420 \Device\HarddiskVolume1\Boot\BCD
0xfffff8a000ade320 0x0000000023a5c320 \SystemRoot\System32\Config\SOFTWARE
0xfffff8a000c96010 0x000000002a4c5010 \??\C:\Windows\ServiceProfiles\NetworkService\NTUSER.DAT
0xfffff8a000d1d010 0x0000000044f5a010 \??\C:\Windows\ServiceProfiles\LocalService\NTUSER.DAT
0xfffff8a001964010 0x0000000011077010 \??\C:\Users\h4ck3rM4n\AppData\Local\Microsoft\Windows\UsrClass.dat
0xfffff8a0019a1010 0x0000000012562010 \??\C:\Users\h4ck3rM4n\ntuser.dat
```

On remarque le NTUser.dat qui est un fichier système du profil d'utilisateur de Windows :

```
0xfffff8a0019a1010 0x0000000012562010 \??\C:\Users\h4ck3rM4n\ntuser.dat
```

Pour le nom de la machine on va directement taper la clé associée :

```shell
└─$ ./vol2 -f chall.raw --profile=Win7SP1x64 printkey -o 0xfffff8a000024010 -K 'ControlSet001\Control\ComputerName\ComputerName' 
Volatility Foundation Volatility Framework 2.6
Legend: (S) = Stable   (V) = Volatile

----------------------------
Registry: \REGISTRY\MACHINE\SYSTEM
Key name: ComputerName (S)
Last updated: 2022-04-08 22:36:24 UTC+0000

Subkeys:

Values:
REG_SZ                        : (S) mnmsrvc
REG_SZ        ComputerName    : (S) H4CK3RC0MPU73R
```

**Flag : MCTF{h4ck3rM4n:H4CK3RC0MPU73R}**

---

## It-remembers-everything 2/3

Difficulté : facile

### Enoncé

> Maintenant que l'utilisateur a été identifié, nous devons comprendre ce qu'il était en train de faire sur la machine avant notre arrivée. Retrouvez le flag.
> 
> Format : MCTF{flag}

### Solve

```
$ ./vol2 --profile=Win7SP1x64 -f chall.raw getsids | grep h4ck3rM4n
Volatility Foundation Volatility Framework 2.6
taskhost.exe (1724): S-1-5-21-3889264649-4192425936-1273705342-1000 (h4ck3rM4n)
dwm.exe (1508): S-1-5-21-3889264649-4192425936-1273705342-1000 (h4ck3rM4n)
explorer.exe (1536): S-1-5-21-3889264649-4192425936-1273705342-1000 (h4ck3rM4n)
mspaint.exe (2924): S-1-5-21-3889264649-4192425936-1273705342-1000 (h4ck3rM4n)
```

On nous demande ce que faisait l'utilisateur, on remarque qu'il était sur **paint**, on va dump le processus

```
$ ./vol2 -f chall.raw --profile=Win7SP1x64 memdump -p 2924 --dump-dir=paint 
Volatility Foundation Volatility Framework 2.6
************************************************************************
Writing mspaint.exe [  2924] to 2924.dmp

$ mv 2924.dmp 2924.data
```

Avec Gimp, on ouvre le fichier en `Données d’image RAW/RAW Image Data`

Il faut jouer avec les valeurs pour trouver le flag

[](./img/flag.png)

**Flag : MCTF{M3m0rY_DuMP}**

---

## It-remembers-everything 3/3

### Enoncé

> Nous avons également trouvé un disque dur qui pourrait potentiellement contenir des informations importantes. Malheureusement, ce disque a été chiffré avec bitlocker.
> Débrouillez vous pour passer outre ce chiffrement et retrouvez le flag.

### Solve

Solution 1 :

```shell
strings chall.raw | grep MCTF
MCTF{b1tl0cKeR_HaS_S0m3_Fl4wS}
```

Solution 2 :

Il nous est dit que le disque est chiffré avec Bitlocker, information que l'on peut vérifier en regardant l'en-tête du système de fichiers. Les volumes chiffrés avec BitLocker auront une signature différente de l'en-tête NTFS standard. Un volume chiffré BitLocker commence par la signature "-FVE-FS-".

```shell
hexdump -C -s $((512*128)) -n 16 chall.vmdk
00010000  eb 58 90 2d 46 56 45 2d  46 53 2d 00 02 08 00 00  |.X.-FVE-FS-.....|
00010010
```

Pour pouvoir monter le disque, il nous faut la clé

Les diques Bitlocker sont chiffrés avec la *Full Volume Encryption Key (FVEK)*

Nous pouvons récupérer cette clé via le dump mémoire

```shell
./vol2 --plugins=plugins/ --profile=Win7SP1x64 -f chall.raw bitlocker

Volatility Foundation Volatility Framework 2.6

[FVEK] Address : 0xfa8001b514f0
[FVEK] Cipher  : AES 128-bit with Diffuser
[FVEK] FVEK    : c6ef551d769f333ed17059601f334c0d
[FVEK] Tweak   : 237413190d5ed1efa5c450bd9281698e
```

```shell
$ sudo bdemount -k c6ef551d769f333ed17059601f334c0d:237413190d5ed1efa5c450bd9281698e -o $((512*128)) chall.vmdk vmdk
bdemount 20190102

$ sudo mount -o ro vmdk/bde1 /media/vmdk

$ ls /media/vmdk 
'$RECYCLE.BIN'   flag.txt  'System Volume Information'

$ cat /media/vmdk/flag.txt
MCTF{b1tl0cKeR_HaS_S0m3_Fl4wS}
```

**Flag : MCTF{b1tl0cKeR_HaS_S0m3_Fl4wS}**
