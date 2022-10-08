# I Will Rock You

## Énoncé

> Trouvez le flag à l'intérieur du firmware.

## Solve

```shell
binwalk -e Firmware.zip 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------

WARNING: Extractor.execute failed to run external extractor 'jar xvf '%e'': [Errno 2] No such file or directory: 'jar', 'jar xvf '%e'' might not be installed correctly
16            0x10            Zip archive data, encrypted at least v2.0 to extract, compressed size: 19065659, uncompressed size: 19111936, name: fs.bin
19065831      0x122EBE7       End of Zip archive, footer length: 22
```

On va bruteforce le zip avec la wordlist **rockyou** comme l'indique le nom du chall :

```shell
zip2john 10.zip > hash
```

```shell
john --wordlist=/usr/share/wordlists/rockyou.txt hash

Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
advenger         (10.zip/fs.bin)     
1g 0:00:00:01 DONE (2022-10-08 00:47) 0.7633g/s 7904Kp/s 7904Kc/s 7904KC/s afermative..adorne2
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

On trouve le password **advenger** :

```shell
unzip 10.zip

Archive:  10.zip
[10.zip] fs.bin password: advenger
  inflating: fs.bin  
```

Un petit combo **strings + grep** pour trouver le flag :

```shell
strings fs.bin | grep -i hackvens
aa idxtape3isdn1 udvboxdvokp24Bleya737AddSearchtfido6017fmaiL$5$gG4RmX4EtzdRNh$KsPMqAOqhUB7vodGuJSw5IJ/g19.JBfmYQ.aHqfqAKD:*ncashHACKVENS{w3_w1ll_R0ck_y0u}
```

**Flag : HACKVENS{w3_w1ll_R0ck_y0u}**