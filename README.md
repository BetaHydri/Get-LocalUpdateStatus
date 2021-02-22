# Get-LocalUpdateStatus

Syntax after import script:
- Get-LocalUpdateStatus -ComputerName localhost -UpdateSearchFilter 'IsHidden=0 and IsInstalled=1'
- Get-LocalUpdateStatus -ComputerName localhost -UpdateSearchFilter 'IsHidden=0 and IsInstalled=0'
- Get-LocalUpdateStatus -ComputerName localhost -UpdateSearchFilter IsHidden=1
- Get-LocalUpdateStatus -ComputerName localhost -UpdateSearchFilter IsInstalled=0
- Get-LocalUpdateStatus -ComputerName localhost -UpdateSearchFilter IsInstalled=1

`Get-LocalUpdateStatus -ComputerName localhost -UpdateSearchFilter IsInstalled=1 | Select-Object -Property KbId, IsInstalled, InstalledOn, Title, SeverityText | Sort-Object -Property InstalledOn -Descending | Format-Table -AutoSize`

Output like:
KbId     |IsInstalled | InstalledOn        |Title                                                                                                                |SeverityText
---------|------------|--------------------|---------------------------------------------------------------------------------------------------------------------|------------
4577586  |      True  |16.02.2021 00:00:00 | Update für die Entfernung von Adobe Flash Player für Windows 10 Version 20H2 für x64-basierten Systemen (KB4577586) | Unspecified
4023057  |      True  |11.02.2021 00:00:00 | 2021-01 Update für Windows 10 Version 20H2 für x64-basierte Systeme (KB4023057)                                     | Unspecified
4052623  |      True  |10.02.2021 00:00:00 | Update für Microsoft Defender Antivirus-Antischadsoftwareplattform – KB4052623 (Version 4.18.2101.9)                | Unspecified
890830   |      True  |09.02.2021 00:00:00 | Windows-Tool zum Entfernen bösartiger Software x64 - v5.86 (KB890830)                                               | Unspecified
4601050  |      True  |09.02.2021 00:00:00 | 2021-02 Kumulatives Update für .NET Framework 3.5 und 4.8 für Windows 10, version 20H2 für x64 (KB4601050)          | Important
4601319  |      True  |09.02.2021 00:00:00 | 2021-02 Kumulatives Update für Windows 10 Version 20H2 für x64-basierte Systeme (KB4601319)                         | Unspecified
4580325  |      True  |20.10.2020 00:00:00 | 2020-10 Sicherheitsupdate für Adobe Flash Player für Windows 10 Version 20H2 für x64-basierte Systeme (KB4580325)   | Critical
4052623  |      True  |01.05.2020 00:00:00 | Update für Windows Defender Antivirus-Antischadsoftwareplattform – KB4052623 (Version 4.18.2001.10)                 | Unspecified
3152281  |      True  |09.06.2017 00:00:00 | Click-to-Run-Updateunterstützung                                                                                    | Unspecified
2467173  |      True  |05.04.2012 00:00:00 | Sicherheitsupdate für Microsoft Visual C++ 2010 Redistributable Package (KB2467173)                                 | Important
925673   |      True | 04.04.2012 00:00:00 | MSXML 6.0 RTM Sicherheitsupdate  (925673)                                                                           | Critical
