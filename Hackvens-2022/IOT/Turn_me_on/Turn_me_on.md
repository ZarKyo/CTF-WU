# Turn me on

## Énoncé

> Reprenons le controle de nos objets connectés avec Tasmota !

## Solve

Doc Tasmota : https://tasmota.github.io/docs/

Avec un peu de recherche, on comprend qu'il est possible d'exécuter des commandes ou de manager l'équipement via une interface Web en étant sur le même WiFi.

(CTF présentiel) Un équipement avec du Tasmota est présent dans la pièce. Un WiFi IOT est disponible et protégé par un password.

Objectif n°1, trouver le password du WiFi.

Avec un **strings** sur le firmware, on récupère pas vraiment d'infos :

```shell
strings firmware.bin

[...]
'P+^&WD
],TB`&U!F$CB
f@DU%\+\C
BoCODz
9KI>AJ:
CQ(["ZB\,]!42T6f*^![4EjT6]'@(^,
jH(["P6[,]j\3T$
d[0@1
45P1_,G%kd
4F$W+Jf
a@.A+Qf
P1_,G%4
\*R(Vb
'3y4
W _,[-TDI:1`OC^DG G'2
]D{'WB2
B3E4E1C2
3I4y0k2
2.433G3
enCy%Z
D3|#K   F*~4]
G$`!D
R6|,E
Q"1gAn
4A7F3G0C1C5JE4Dj46F52y
D\5E22+G0D21
wq4/D.^C3D4A1B2h
btAk 0
s3C3D4A1B2C3D4A1B2C3D4A1B2C3D4A1B2C3D4A1B2C3D4A1B2C
0A1J2C3@4A1R2C3d4A1
2C3D4A1B2C3D4A1
2C3D5d
(PA_#\CZ*RAx
`c]+@aX,
y`<B
[...]
```

Je suis allé comparer le firmware donné pour le chall avec les firmwares officiels sur le site de Tasmota : http://ota.tasmota.com/tasmota/release/ 

```shell
strings tasmota.bin # english
[...]
Learn failed
Tasmota
Status:
WifiConfig %d
LOG_LEVEL_INFO
LOG_LEVEL_NONE
Scanning
Toggle
RESULT
UPDATE
"sequence"
"switch"
"on"
"color
"bright"
"mode"
SETTING
=exit
&#9660;
&#9650;
save
BL09XX
[...]
```

```shell
strings tasmota-FR.bin # french
[...]
chec de connexion avec l'AP, expir
Successful
Testing
Busy
Not Started
chec de connexion car aucune adresse IP n'a 
chec de connexion car l'AP ne peut-
tre contact
chec de connexion
Dimmer1:
Dimmer2:
Status
Setled:
%s:%02x:11-%02x
ADE7953
null
AT+START
AT+SEND=ok
AT+SEND=fail
AT+STATUS=4
[...]
```

On remarque que les intrucstions et/ou informations de config sont bien présentes dans le firmware. On peut déduire que le firmware du chall est chiffré.

On peut essayer de bruteforce le firware avec du XOR : https://wiremask.eu/tools/xor-cracker/

On obtient un fichier XOR avec la clé : **A1B2C3D4 | 41 31 42 32 43 33 44 34**

```shell
strings plain-firmware.bin
[...]
0123456789ABCDEF
%s%s%s%s
#4ckVens22!CTF
Hackvens-CTF-IOT
Connect failed with AP timeout
Successful
Testing
Busy
Not Started
Connect failed as no IP address received
Connect failed as AP cannot be reached
Connect failed
%04d
Time
Referer
```

Avec un peu de guessing on trouve le password du Wifi.

**Pass du wifi : #4ckVens22!CTF**

Maintenant, il faut trouver l'URL sur laquelle se connecter. Selon la documentation, une URL est définie par défaut : http://192.168.4.1

Or ici l'URL est différente car l'objet connecté a déjà été configuré :

```shell
strings plain-firmware.bin | grep -i -A 10 -B 10 192.168.  

BASE
FLAG
TPL: Converting template ...
NAME
{"Time":"%s"
{"Time":%u
{"Time":"%s","Epoch":%u
SRC: %s
Blocked Loop
255.255.255.0
192.168.99.1
0.0.0.0
HOLD
TOGGLE
#4ckVens22!CTF
Hackvens-CTF-IOT
192.168.15.1
192.168.15.2
Tasmota4
Tasmota3
Tasmota2
CFG: Use defaults
CFG: Loaded from flash at %X, Count %lu
CFG: Saved to flash at %X, Count %d, Bytes %d
CFG: CR %d/%d, Busy %d
CFG: Text overflow by %d char(s)
Config_%s_%s.dmp
APP: Not enough space
```

**URL de management : http://192.168.15.2/**

On presse le bouton présent sur l'interface et le flag apparaît.

**Flag : HACKVENS{x0r_is_n07_53cur3}**
