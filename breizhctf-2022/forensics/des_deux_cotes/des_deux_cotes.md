# Des deux côtés

Auteur: Worty

Format : BZHCTF{}

## Partie 1/2

### Énoncé

> Voir les deux côtés de quelque chose, c'est toujours bon non? 
> 
> Vous êtes une APT et un de vos collègues a volé une machine chez une entreprise du CAC40, malheureusement, celle-ci ne veut plus démarrer.. 
> 
> Votre collègue étant un hacker en herbe, il a pensé à faire un dump mémoire avant que la machine rende l'âme ! Retrouvez le fichier qui contient des données confidentielles dans ce dump mémoire !

### Solve

```shell
$ sudo vol -f memory.dmp windows.info

Kernel Base    0x8283e000
DTB    0x185000
Symbols    file:///usr/lib/python3.10/site-packages/volatility3/symbols/windows/ntkrpamp.pdb/684DA42A30CC450F81C535B4D18944B1-2.json.xz
Is64Bit    False
IsPAE    True
primary    0 WindowsIntelPAE
memory_layer    1 WindowsCrashDump32Layer
base_layer    2 FileLayer
KdDebuggerDataBlock    0x82968c28
NTBuildLab    7601.17514.x86fre.win7sp1_rtm.10
CSDVersion    1
KdVersionBlock    0x82968c00
Major/Minor    15.7601
MachineType    332
KeNumberProcessors    1
SystemTime    2022-02-23 19:29:05
NtSystemRoot    C:\Windows
NtProductType    NtProductWinNt
NtMajorVersion    6
NtMinorVersion    1
PE MajorOperatingSystemVersion    6
PE MinorOperatingSystemVersion    1
PE Machine    332
PE TimeDateStamp    Sat Nov 20 08:42:49 2010
```

```shell
$ sudo vol -f memory.dmp windows.filescan > filescan.txt
```

Les fichiers intéressant sont : 

```
0x3ea68308 \Users\Daniel\Documents\RH-Documents\Confidential\Employe Secret.txt 128

0x3fd0af80 \Users\Daniel\Documents\RH-Documents\Confidential\Resultat Entretien 2021.txt 128

0x3f17b1e8 \Users\Daniel\Documents\RH-Documents\Confidential 128

0x3f1a3f80 \Users\Daniel\Documents\RH-Documents\Confidential 128
```

Avec **vol2** :

```shell
$ ./vol2 -f memory.dmp imageinfo

Volatility Foundation Volatility Framework 2.6
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x86_23418, Win7SP0x86, Win7SP1x86 (Instantiated with WinXPSP2x86)
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)
                     AS Layer2 : WindowsCrashDumpSpace32 (Unnamed AS)
                     AS Layer3 : FileAddressSpace (/home/zarkyo/breizhctf/forensics/deux-cote/memory.dmp)
                      PAE type : PAE
                           DTB : 0x185000L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2022-02-23 19:29:05 UTC+0000
     Image local date and time : 2022-02-23 11:29:05 -0800
```

On va regarder si les fichiers ont été ouverts avec notepad

```shell
$ ./vol2 -f memory.dmp --profile=Win7SP1x86 cmdline

notepad.exe pid:   3232
Command line : "C:\Windows\system32\NOTEPAD.EXE" C:\Users\Daniel\Documents\RH-Documents\Confidential\Resultat Entretien 2021.txt
************************************************************************
notepad.exe pid:   3732
Command line : "C:\Windows\system32\NOTEPAD.EXE" C:\Users\Daniel\Documents\RH-Documents\Confidential\Employe Secret.txt
```

Bingo ! On va pouvoir dump les processus et essayer de récuperer du contenu de ces fichiers 

```shell
$ ./vol2 -f memory.dmp --profile=Win7SP1x86 memdump --dump-dir=./ -p 3732
```

```shell
$ strings -e l ./3732.dmp > notepad1.txt
```

Dans **notepad1.txt** on découvre des informations interessant

```
[...]
Le nouvel employ
, Matthieu Delkique va nous rejoindre (ouf !)
Ses identifiants de connexion seront :
m.delkique@vulncorp.fr/MatthieuVulnCorp123!
Attenion 
 bien lui fournir sa signature :
QlpIQ1RGe2ZyMzNfY3IzZDNudGk0bHN9Cg==
 oye Secret.txt
.txt
Fran
ais (France)
\Win
[...]
```

```shell
$ echo 'QlpIQ1RGe2ZyMzNfY3IzZDNudGk0bHN9Cg==' | base64 -d
BZHCTF{fr33_cr3d3nti4ls}
```

**Flag : BZHCTF{fr33_cr3d3nti4ls}**

---

## Partie 2/2

### Énoncé

> Voir les deux côtés de quelque chose, c'est toujours bon non?
> 
> Un de vos employés s'est fait voler sa machine il y a 3 heures, heureusement, votre SI est bien configuré est des snapshots mémoires sont réalisées toutes les 2 heures ! Votre employé vous affirme qu'il a reçu un mail officiel de ses supérieurs pour télécharger une nouvelle application l'aidant dans son travail.. Votre but est d'identifier le nom de ce fichier, et de trouver sur quelle ip ainsi que sur quel port la backdoor s'est connectée !
> 
> Le fichier est le même que pour le premier challenge

Format : BZHCTF{malveillant.exe-ip:port}

### Solve

```shell
$ sudo vol -f memory.dmp windows.pslist
Volatility 3 Framework 1.0.1
Progress:  100.00        PDB scanning finished                     
PID    PPID    ImageFileName    Offset(V)    Threads    Handles    SessionId    Wow64    CreateTime    ExitTime    File output

4    0    System    0x84133270    77    511    N/A    False    2022-02-23 18:09:02.000000     N/A    Disabled
224    4    smss.exe    0x854f4020    2    29    N/A    False    2022-02-23 18:09:02.000000     N/A    Disabled
304    296    csrss.exe    0x85748030    9    338    0    False    2022-02-23 18:09:03.000000     N/A    Disabled
340    296    wininit.exe    0x85b9bd40    3    75    0    False    2022-02-23 18:09:03.000000     N/A    Disabled
352    332    csrss.exe    0x85b9c578    9    209    1    False    2022-02-23 18:09:03.000000     N/A    Disabled
392    332    winlogon.exe    0x85c23d40    5    130    1    False    2022-02-23 18:09:04.000000     N/A    Disabled
444    340    services.exe    0x85cac030    7    196    0    False    2022-02-23 18:09:04.000000     N/A    Disabled
452    340    lsass.exe    0x85cba2d8    6    558    0    False    2022-02-23 18:09:04.000000     N/A    Disabled
468    340    lsm.exe    0x85cbc620    9    141    0    False    2022-02-23 18:09:04.000000     N/A    Disabled
576    444    svchost.exe    0x85f2bc08    9    353    0    False    2022-02-23 18:09:04.000000     N/A    Disabled
636    444    svchost.exe    0x85f3d030    7    250    0    False    2022-02-23 18:09:05.000000     N/A    Disabled
860    444    sppsvc.exe    0x854f3668    4    147    0    False    2022-02-24 03:09:07.000000     N/A    Disabled
900    444    svchost.exe    0x84c07030    14    314    0    False    2022-02-24 03:09:08.000000     N/A    Disabled
924    444    svchost.exe    0x84c08800    40    1256    0    False    2022-02-24 03:09:08.000000     N/A    Disabled
972    444    svchost.exe    0x84c8d030    19    450    0    False    2022-02-24 03:09:08.000000     N/A    Disabled
1004    972    audiodg.exe    0x84cc6030    4    121    0    False    2022-02-24 03:09:08.000000     N/A    Disabled
1044    444    svchost.exe    0x85aa6810    10    265    0    False    2022-02-24 03:09:09.000000     N/A    Disabled
1068    444    svchost.exe    0x84cd8410    19    490    0    False    2022-02-24 03:09:09.000000     N/A    Disabled
1180    444    TrustedInstall    0x84d04d40    6    261    0    False    2022-02-24 03:09:10.000000     N/A    Disabled
1340    444    spoolsv.exe    0x85f9b030    12    293    0    False    2022-02-24 03:09:10.000000     N/A    Disabled
1380    444    svchost.exe    0x85fe0030    19    315    0    False    2022-02-24 03:09:10.000000     N/A    Disabled
1692    444    svchost.exe    0x85550718    6    94    0    False    2022-02-24 03:09:11.000000     N/A    Disabled
772    444    taskhost.exe    0x84e3e4d0    8    208    1    False    2022-02-24 03:09:17.000000     N/A    Disabled
848    900    dwm.exe    0x84c7ac88    3    71    1    False    2022-02-24 03:09:17.000000     N/A    Disabled
880    756    explorer.exe    0x84c7f9d8    32    881    1    False    2022-02-24 03:09:17.000000     N/A    Disabled
1864    880    regsvr32.exe    0x84e79508    0    -    1    False    2022-02-24 03:10:06.000000     2022-02-24 03:10:07.000000     Disabled
1868    444    svchost.exe    0x85fc0030    11    144    0    False    2022-02-24 03:11:11.000000     N/A    Disabled
1724    444    svchost.exe    0x84dde0b0    9    311    0    False    2022-02-24 03:11:11.000000     N/A    Disabled
3820    444    msiexec.exe    0x8430dc38    6    305    0    False    2022-02-23 19:18:52.000000     N/A    Disabled
2660    444    armsvc.exe    0x8545d368    6    244    0    False    2022-02-23 19:19:17.000000     N/A    Disabled
3268    444    SearchIndexer.    0x842a3168    11    522    0    False    2022-02-23 19:19:24.000000     N/A    Disabled
2484    2660    AdobeARMHelper    0x84356ca8    0    -    0    False    2022-02-23 19:20:53.000000     2022-02-23 19:20:54.000000     Disabled
2360    816    firefox.exe    0x85ee3d40    0    -    1    False    2022-02-23 19:24:17.000000     2022-02-23 19:24:39.000000     Disabled
3936    880    RH-Appli-Conne    0x84e17570    1    36    1    False    2022-02-23 19:24:45.000000     N/A    Disabled
1668    880    RH-Appli-Conne    0x843485b0    3    94    1    False    2022-02-23 19:25:07.000000     N/A    Disabled
1472    1668    cmd.exe    0x84273030    0    -    1    False    2022-02-23 19:25:24.000000     2022-02-23 19:25:27.000000     Disabled
1152    924    WMIADAP.exe    0x8549b108    5    86    0    False    2022-02-23 19:27:21.000000     N/A    Disabled
3072    576    WmiPrvSE.exe    0x84283830    8    115    0    False    2022-02-23 19:27:21.000000     N/A    Disabled
3232    880    notepad.exe    0x84f7e630    1    63    1    False    2022-02-23 19:27:43.000000     N/A    Disabled
3732    880    notepad.exe    0x86081218    1    63    1    False    2022-02-23 19:27:46.000000     N/A    Disabled
3540    880    RH-Appli-Conne    0x84f3cd40    1    20    1    False    2022-02-23 19:27:54.000000     N/A    Disabled
3504    880    RH-Appli-Conne    0x842ef7e0    5    99    1    False    2022-02-23 19:28:06.000000     N/A    Disabled
2404    3504    cmd.exe    0x84da8938    0    -    1    False    2022-02-23 19:28:10.000000     2022-02-23 19:28:12.000000     Disabled
```

```shell
$ sudo vol -f dumpfile/memory.dmp windows.pstree      

Volatility 3 Framework 1.0.1
Progress:  100.00               PDB scanning finished                     
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime

4       0       System  0x84da8938      77      511     N/A     False   2022-02-23 18:09:02.000000      N/A
* 224   4       smss.exe        0x84da8938      2       29      N/A     False   2022-02-23 18:09:02.000000      N/A
304     296     csrss.exe       0x84da8938      9       338     0       False   2022-02-23 18:09:03.000000      N/A
340     296     wininit.exe     0x84da8938      3       75      0       False   2022-02-23 18:09:03.000000      N/A
* 468   340     lsm.exe 0x84da8938      9       141     0       False   2022-02-23 18:09:04.000000      N/A
* 452   340     lsass.exe       0x84da8938      6       558     0       False   2022-02-23 18:09:04.000000      N/A
* 444   340     services.exe    0x84da8938      7       196     0       False   2022-02-23 18:09:04.000000      N/A
** 576  444     svchost.exe     0x84da8938      9       353     0       False   2022-02-23 18:09:04.000000      N/A
*** 3072        576     WmiPrvSE.exe    0x84da8938      8       115     0       False   2022-02-23 19:27:21.000000      N/A
** 1692 444     svchost.exe     0x84da8938      6       94      0       False   2022-02-24 03:09:11.000000      N/A
** 1724 444     svchost.exe     0x84da8938      9       311     0       False   2022-02-24 03:11:11.000000      N/A
** 900  444     svchost.exe     0x84da8938      14      314     0       False   2022-02-24 03:09:08.000000      N/A
*** 848 900     dwm.exe 0x84da8938      3       71      1       False   2022-02-24 03:09:17.000000      N/A
** 1380 444     svchost.exe     0x84da8938      19      315     0       False   2022-02-24 03:09:10.000000      N/A
** 772  444     taskhost.exe    0x84da8938      8       208     1       False   2022-02-24 03:09:17.000000      N/A
** 860  444     sppsvc.exe      0x84da8938      4       147     0       False   2022-02-24 03:09:07.000000      N/A
** 2660 444     armsvc.exe      0x84da8938      6       244     0       False   2022-02-23 19:19:17.000000      N/A
*** 2484        2660    AdobeARMHelper  0x84da8938      0       -       0       False   2022-02-23 19:20:53.000000      2022-02-23 19:20:54.000000 
** 924  444     svchost.exe     0x84da8938      40      1256    0       False   2022-02-24 03:09:08.000000      N/A
*** 1152        924     WMIADAP.exe     0x84da8938      5       86      0       False   2022-02-23 19:27:21.000000      N/A
** 3268 444     SearchIndexer.  0x84da8938      11      522     0       False   2022-02-23 19:19:24.000000      N/A
** 972  444     svchost.exe     0x84da8938      19      450     0       False   2022-02-24 03:09:08.000000      N/A
*** 1004        972     audiodg.exe     0x84da8938      4       121     0       False   2022-02-24 03:09:08.000000      N/A
** 1068 444     svchost.exe     0x84da8938      19      490     0       False   2022-02-24 03:09:09.000000      N/A
** 1868 444     svchost.exe     0x84da8938      11      144     0       False   2022-02-24 03:11:11.000000      N/A
** 3820 444     msiexec.exe     0x84da8938      6       305     0       False   2022-02-23 19:18:52.000000      N/A
** 1180 444     TrustedInstall  0x84da8938      6       261     0       False   2022-02-24 03:09:10.000000      N/A
** 1044 444     svchost.exe     0x84da8938      10      265     0       False   2022-02-24 03:09:09.000000      N/A
** 1340 444     spoolsv.exe     0x84da8938      12      293     0       False   2022-02-24 03:09:10.000000      N/A
** 636  444     svchost.exe     0x84da8938      7       250     0       False   2022-02-23 18:09:05.000000      N/A
352     332     csrss.exe       0x84da8938      9       209     1       False   2022-02-23 18:09:03.000000      N/A
392     332     winlogon.exe    0x84da8938      5       130     1       False   2022-02-23 18:09:04.000000      N/A
880     756     explorer.exe    0x84da8938      32      881     1       False   2022-02-24 03:09:17.000000      N/A
* 3936  880     RH-Appli-Conne  0x84da8938      1       36      1       False   2022-02-23 19:24:45.000000      N/A
* 3232  880     notepad.exe     0x84da8938      1       63      1       False   2022-02-23 19:27:43.000000      N/A
* 1668  880     RH-Appli-Conne  0x84da8938      3       94      1       False   2022-02-23 19:25:07.000000      N/A
** 1472 1668    cmd.exe 0x84da8938      0       -       1       False   2022-02-23 19:25:24.000000      2022-02-23 19:25:27.000000 
* 1864  880     regsvr32.exe    0x84da8938      0       -       1       False   2022-02-24 03:10:06.000000      2022-02-24 03:10:07.000000 
* 3504  880     RH-Appli-Conne  0x84da8938      5       99      1       False   2022-02-23 19:28:06.000000      N/A
** 2404 3504    cmd.exe 0x84da8938      0       -       1       False   2022-02-23 19:28:10.000000      2022-02-23 19:28:12.000000 
* 3732  880     notepad.exe     0x84da8938      1       63      1       False   2022-02-23 19:27:46.000000      N/A
* 3540  880     RH-Appli-Conne  0x84da8938      1       20      1       False   2022-02-23 19:27:54.000000      N/A
2360    816     firefox.exe     0x84da8938      0       -       1       False   2022-02-23 19:24:17.000000      2022-02-23 19:24:39.000000 
```

On remarque que **RH-Appli-Conne** lance un **cmd**.

Les autres processus semble normaux

```shell
$ sudo vol -f dumpfile/memory.dmp windows.netscan      

Volatility 3 Framework 1.0.1
Progress:  100.00               PDB scanning finished                     
Offset  Proto   LocalAddr       LocalPort       ForeignAddr     ForeignPort     State   PID     Owner   Created

0x3de43f50      UDPv4   192.168.80.131  137     *       0               4       System  2022-02-23 19:26:24.000000 
0x3de61008      UDPv4   192.168.80.131  138     *       0               4       System  2022-02-23 19:26:24.000000 
[...]
0x3e1d15e8      TCPv4   192.168.80.131  49636   146.59.156.82   1337    ESTABLISHED     3936    RH-Appli-Conne  -
[...]
0x3e491b48      TCPv4   192.168.80.131  49637   146.59.156.82   1337    ESTABLISHED     1668    RH-Appli-Conne  -
[...]
0x3f09edf8      TCPv4   192.168.80.131  49644   146.59.156.82   1337    ESTABLISHED     3540    RH-Appli-Conne  -
[...]
0x3fcaf2a0      TCPv4   192.168.80.131  49645   146.59.156.82   1337    ESTABLISHED     3504    RH-Appli-Conne  -
[...]
```

L'application établis une connexion en **146.59.156.82:1337**

En lancant un `cmdline`, on obtient le nom complet de l'executable

**Flag : BZHCTF{RH-Appli-Connect.exe-146.59.156.82:1337}**
