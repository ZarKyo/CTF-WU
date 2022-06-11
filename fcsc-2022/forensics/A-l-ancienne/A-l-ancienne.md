Catégorie : Forensics

Difficulté : :star:

---

# À l'ancienne

## Ennoncé

>Vous devez récupérer et analyser les données échangées dans cette capture. On préfère prévenir, avant de paniquer, il va falloir se décontracter et décompresser pour faire ça tranquillement.
>
>SHA256(cap) = 27117fc9487e8ca1a54f7d6a55f39b3223153451a8df41bb02488c2a99dbf059.

---

## Solve

```shell
└─$ file cap            
cap: Sniffer capture file - version 4.0 (Ethernet)
```

On ouvre le fichier avec wireshark, on parcour rapidement le fichier.

Il n'y a pratiquement que des requêtes DNS, l'objectif est donc de récupérer les données de ses requêtes

PI :

Format requêtes DNS --> `data.data.domain`

Ici les données sont encondées en base64 et certain caractère ont été remplacer par d'autre.

Pour la base64 : `* = +`

Pour le parsing : `-. = .`

En scriptant avec python, on peut additioner tous les chaînes de base64, les décoder et en faire un fichier

premier jet de script :

```py
import pyshark
#import codecs

last_qry = ""
data = ""
      
with pyshark.FileCapture('./cap', display_filter=('dns')) as packets:

    packets.load_packets()

    for pkt in packets:

      # parsing
      qry = pkt.dns.qry_name

      qry = qry.replace("*","+").strip().split("-.")
      qry = ''.join(qry)
      
      if last_qry != qry:
        data += qry

      last_qry = qry

print(data)
```

On récupère la base64 --> cyberchef et on récupère un fichier

```shell
$ file passwd         
passwd: gzip compressed data, was "passwd", last modified: Thu Mar 17 12:45:11 2022, from Unix, original size modulo 2^32 3365188005

$ mv passwd passwd.gz 

$ gunzip -d passwd.gz                                                                                                                           ✔ 

gzip: passwd.gz: invalid compressed data--crc error

gzip: passwd.gz: invalid compressed data--length error
```

Je décide de regader dans un premier temps si le header n'est pas un peu endommagé 

Header normal : `1f  8b  08  08`
```shell
xxd -l 18 files/passwd.gz                                                                                                                         1 ✘ 
00000000: 1f8b 0808 572d 3362 0003 7061 7373 7764  ....W-3b..passwd
00000010: 0095                                     ..
```

Pas d'anomalie, quand on regade de plus près la base64 et les requêtes, on s'aperçoit que plusieurs fichier sont échangés

Deuxième jet de script :

```py
import pyshark
from base64 import b64decode

last_qry = ""
data = {}
      
with pyshark.FileCapture('./cap', display_filter=('dns')) as packets:

    packets.load_packets()

    for pkt in packets:

      # parsing
      qry = pkt.dns.qry_name

      qry = qry.replace("*","+").strip().split("-.")
      filename = qry[-1]
      qry = ''.join(qry)
      qry = qry.replace(filename,"").strip()  
      
      if last_qry != qry:

        if filename not in data:
          data[filename] = qry
        else:
          data[filename] += qry

      last_qry = qry

for key,value in data.items():
    with open(f'files/{b64decode(key).decode()}.gz','wb+') as f:
        f.write(b64decode(value))
```

transformer le file en .doc --> rename

**Flag : FCSC{18e955473d2e12feea922df7e1f578d27ffe977e7fa5b6f066f7f145e2543a92}**
