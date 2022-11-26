# Vivre pas cher

Difficulté : Moyen

## Énoncé

> Notre serveur a été piraté. C'est une évidence.
> Ils dévoilent notre code source sans arrêt, dès que nous le mettons à jour.
> Vous devez trouver l'origine de cette backdoor dès que possible.
> Annie Massion, Services postaux

## Solve

monter l'image :

```shell
sudo modprobe nbd
sudo qemu-nbd -r -c /dev/nbd1 cheap-life.img
sudo mount -o ro,noload /dev/nbd1p1 /mnt/tmp
```

### Solve 1

On cherche une backdoor :

```shell
sudo grep -ari backdoor tmp   

tmp/usr/share/perl/5.32.1/perl5db.pl:    return if $skipCvGV;    # Backdoor to avoid problems if XS broken...
tmp/usr/share/perl/5.32.1/Dumpvalue.pm:  return if $self->{skipCvGV};   # Backdoor to avoid problems if XS broken...
tmp/usr/share/perl/5.32.1/CPAN.pm:                # backdoor: I could not find a way to record sessions
tmp/usr/share/perl/5.32.1/dumpvar.pl:  return if $skipCvGV;             # Backdoor to avoid problems if XS broken...

[...]

tmp/usr/sbin/groupdel:

[...]

tmp/etc/systemd/system/systembd.service:Description=backdoor
tmp/etc/systemd/system/systembd.service:ExecStart=/usr/sbin/groupdel start_backdoor
tmp/lib/libsysd.so:ELF>p@7@8

[...]

)W__gmon_start___ITM_deregisterTMCloneTable_ITM_registerTMCloneTable__cxa_finalizestart_backdoorprintfsleepputslibc.so.6GLIBC_2.2.5vu▒i        �▒▒>�?�?�?�?▒@ @(@0@��H�H��/H��t��H���5�/�%�/@�%�/h������%�/h������%�/h������%�/h�����H�=�/H��/H9�tH�V/H��t    �����H�=�/H�5�/H)�H��H��?H��H�H��tH�%/H����fD�����=M/u+UH�=/H��t
                                                                                                                                                                                                        H�=-�Y����d����%/]������w���UH��H���}��}���1u(H��H�Ǹ�����H��H�Ǹ�����������H��H�����������H�H��debugREdIQUNLe1N5c3RlbURJc0FGcmVuY2hFeHByZXNzaW9uQWJvdXRMaXZpbmdPdXRPZlJlc291cmNlZnVsbmVzc1dpdGhMaXR0bGVNb25leX0KProgram running as intended.▒����4����\zRx

[...]

tmp/lib/libsysd.so: ,=
[...]
```

On ne le sait pas encore mais le flag est juste sous nos yeux. Avec ce `grep`, on a pu trouver différents fichiers qui potentiellement contiennent du code backdoor. 

Si on parcourt rapidement les fichiers lister précédemment, on remarque le fichier `lib/libsysd.so` contient le flag.

### Solve 2

On connait le patern DGHACK du flag, potentiellement de la base64 

`DGHACK = REdIQUNLewo`

```shell
sudo grep -ari "REdIQUNL" tmp/
[...]
REdIQUNLe1N5c3RlbURJc0FGcmVuY2hFeHByZXNzaW9uQWJvdXRMaXZpbmdPdXRPZlJlc291cmNlZnVsbmVzc1dpdGhMaXR0bGVNb25leX0K
[...]
```

```shell
echo 'REdIQUNLe1N5c3RlbURJc0FGcmVuY2hFeHByZXNzaW9uQWJvdXRMaXZpbmdPdXRPZlJlc291cmNlZnVsbmVzc1dpdGhMaXR0bGVNb25leX0K' | base64 -d
DGHACK{SystemDIsAFrenchExpressionAboutLivingOutOfResourcefulnessWithLittleMoney}
```

### Solve 3

Cette fois-ci avec un tool

```shell
stringcheese DGHACK{ --file cheap-life.img

This is a large file and may take a long time to be treated, do you wish to continue? (y/N) : y
MATCH FOUND! In stream, using encoding base64:                                            
DGHACK{SystemDIsAFrenchExpressionAboutLivingOutOfResourcefulnessWithLittleMoney}
```

**Flag : DGHACK{SystemDIsAFrenchExpressionAboutLivingOutOfResourcefulnessWithLittleMoney}**