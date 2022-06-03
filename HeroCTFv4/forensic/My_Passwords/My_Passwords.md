# My Passwords

## Ennoncé

> We have exfiltrated data from a malicious person's computer and we need his pastebin password.
>
> Unfortunately, the file system dump was damaged, so the only thing we were able to recover is provided to you.
>
> Can you recover his password?

Catégorie : Forensics

Difficulté : facile

Format : Hero{pastebin_mdp}

Author : Worty

## Solve

On découvre un dump firefox avec 2 profils, mais 1 seul va nous intérésser

key4db.db associé à logins.json sont indiqués comme étant les fichiers conservant les passwords.

logins.json :

```json
{
    "id":5,
    "hostname":"https://pastebin.com",
    "httpRealm":null,
    "formSubmitURL":"https://pastebin.com",
    "usernameField":"LoginForm[username]",
    "passwordField":"LoginForm[password]",
    "encryptedUsername":"MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECA1XFI5iCJMzBBAWSQBwp7VKo2cYSW+cW8RD","encryptedPassword":"MEIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECOThP7XPXvkcBBhQMfiZl4Yd5Yv71osCsB//O4sEWgD4qX4=",
    "guid":"{851558dc-4eac-4c4a-874a-92f81bfdd623}",
    "encType":1,
    "timeCreated":1653318181387,
    "timeLastUsed":1653318181387,
    "timePasswordChanged":1653318181387,
    "timesUsed":1
}
```

On a ici le tools pour déchiffrer les password : https://github.com/unode/firefox_decrypt

Cependant notre profil possède un `master password`

On va pouvoir récupérer ce password via brute-force 

https://gitcode.net/mirrors/hashcat/hashcat/-/blob/4b6654b5030764dbfffd7905645b0d9ca8b9a5ab/tools/mozilla2hashcat.py?from_codechina=yes

```shell
python tools_mozilla2hashcat.py Firefox/Profiles/nh7x18gj.default-release/key4.db > hash.hash
```

```shell
hashcat -h | grep key4.db

  26100 | Mozilla key4.db | Password Manager
```

```shell
hashcat -a 0 -m 26100 hash.hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.5) starting

[...]

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 2 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

[...]

$mozilla$*AES*85d53a4628055f9e4cc1238fed092b5444b24eee*21af57842b20ac2bc38800d1c68f43bad2dcccb6fac2a36b870e36af92c56b21*10000*040ec632b9dc589c08217fad483f1354*9a8dee8e8bc13c177a45236cc944540e:fartknocker
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 26100 (Mozilla key4.db)
Hash.Target......: $mozilla$*AES*85d53a4628055f9e4cc1238fed092b5444b24...44540e
Time.Started.....: Sat May 28 16:46:07 2022 (16 secs)
Time.Estimated...: Sat May 28 16:46:23 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     4233 H/s (11.76ms) @ Accel:256 Loops:256 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 67584/14344385 (0.47%)
Rejected.........: 0/67584 (0.00%)
Restore.Point....: 65536/14344385 (0.46%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:9984-9999
Candidate.Engine.: Device Generator
Candidates.#1....: ryanscott -> slipknot13
Hardware.Mon.#1..: Temp: 79c Util: 97%

Started: Sat May 28 16:45:31 2022
Stopped: Sat May 28 16:46:25 2022
```

```shell
echo "fartknocker" | python3 firefox_decrypt.py Firefox/ --choice 2 --no-interactive
Reading Master password from standard input:

Website:   https://fr-fr.facebook.com
Username: 'pauljacquet@gmail.com'
Password: 'YjnHQKLSLPWO8566'

Website:   https://www.reddit.com
Username: 'paul.jacqu3t'
Password: 'LKANSNHJSLPAMKncjfh8556'

Website:   https://twitter.com
Username: 'pauljacquet@gmail.com'
Password: 'A98zNbbJAKQLW10Q'

Website:   https://accounts.google.com
Username: 'pauljacquet@gmail.com'
Password: 'MlnWJQIAhdtTZ42A589S'

Website:   https://pastebin.com
Username: 'paul_jacquet'
Password: 'NSjjqnIAMSOAPD52698'

Website:   https://pastebin.com
Username: ''
Password: 'JnQKLWMpaoIEYGFNH5Q69Z'
```

**Flag : Hero{JnQKLWMpaoIEYGFNH5Q69Z}**