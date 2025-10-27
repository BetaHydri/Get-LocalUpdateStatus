# Get-LocalUpdateStatus

A PowerShell function that enumerates Windows Updates (both installed and missing) on local or remote computers and returns detailed update information as PowerShell objects. **Now includes the ability to download update files directly from Microsoft, support for air-gapped environments through export/import functionality, and WSUS offline scanning using wsusscn2.cab!**

## Description

This script provides detailed information about Windows Updates including:
- Installed updates
- Missing/available updates  
- Hidden updates
- Update metadata (KB IDs, security bulletins, CVE IDs, severity, etc.)
- Installation dates and restart requirements
- **NEW: Direct download capability for updates with available download URLs**
- **NEW: Export/Import functionality for air-gapped or restricted network environments**
- **NEW: WSUS offline scanning using Microsoft's wsusscn2.cab for completely offline environments**

## Requirements

- **PowerShell 4.0** or higher
- **Administrator privileges** required
- User must have admin rights on target computers for remote queries
- Uses Microsoft Update Session COM objects

## Installation

1. Download the `Get-LocalUpdateStatus.ps1` file
2. Import the script:
   ```powershell
   . .\Get-LocalUpdateStatus.ps1
   ```

## Parameters

### ComputerName (Required)
- **Type:** String
- **Description:** Target computer name (use 'localhost' for local machine)

### UpdateSearchFilter (Required)
- **Type:** ValidateSet String
- **Valid Values:**
  - `'IsHidden=0 and IsInstalled=1'` - Visible installed updates
  - `'IsHidden=0 and IsInstalled=0'` - Visible missing updates  
  - `'IsInstalled=1'` - All installed updates
  - `'IsInstalled=0'` - All missing updates
  - `'IsHidden=0'` - All visible updates
  - `'IsHidden=1'` - Hidden updates

### DownloadUpdates (Optional)
- **Type:** Switch  
- **Description:** Enable download mode to automatically download update files when DownloadURL is available
- **Default:** Disabled

### InstallUpdates (Optional)
- **Type:** Switch
- **Description:** Automatically install downloaded updates using DISM (.cab) or WUSA (.msu)
- **Requirements:** Must be used with `-DownloadUpdates` parameter
- **Supported Formats:** .cab files (via DISM), .msu files (via WUSA)
- **Installation Flags:** Uses /Quiet /NoRestart (DISM) and /quiet /norestart (WUSA)
- **Admin Required:** Requires Administrator privileges for installation
- **Default:** Disabled### DownloadPath (Optional)
- **Type:** String
- **Description:** Directory path where downloaded update files will be saved
- **Default:** `$env:TEMP\WindowsUpdates`
- **Validation:** Path must exist or be creatable

### ExportReport (Optional)
- **Type:** String
- **Description:** Export scan results to XML file for later import on another machine
- **Usage:** Automatically adds `.xml` extension if not provided
- **Use Case:** Perfect for air-gapped environments

### ImportReport (Required for Import Mode)
- **Type:** String
- **Description:** Import previously exported XML report for viewing or downloading
- **Validation:** File must exist
- **Parameter Set:** Mutually exclusive with ComputerName (different operation mode)

### WSUSOfflineScan (Required for WSUS Offline Mode)
- **Type:** Switch
- **Description:** Enable WSUS offline scan mode using wsusscn2.cab
- **Use Case:** Perfect for completely air-gapped environments
- **Parameter Set:** Works with ComputerName and UpdateSearchFilter parameters

### UpdateSearchFilter (Required for WSUS Offline Mode)
- **Type:** ValidateSet String
- **Description:** Same filter options as regular scan mode
- **Valid Values:** All standard filter options supported
- **Position:** 4 (for WSUS offline scan parameter set)

### WSUSScanFile (Optional for WSUS Offline Mode)
- **Type:** String
- **Description:** Path to existing wsusscn2.cab file for offline scanning
- **Validation:** File must exist if provided
- **Path Support:** Supports both relative (.\wsusscn2.cab) and absolute paths
- **Default:** Auto-download if not specified and DownloadWSUSScanFile is used

### DownloadWSUSScanFile (Optional for WSUS Offline Mode)
- **Type:** Switch
- **Description:** Download latest wsusscn2.cab from Microsoft's official source
- **URL:** https://catalog.s.download.windowsupdate.com/microsoftupdate/v6/wsusscan/wsusscn2.cab

### WSUSScanFileDownloadPath (Optional for WSUS Offline Mode)
- **Type:** String
- **Description:** Directory path where wsusscn2.cab will be downloaded
- **Default:** `$env:TEMP`

## Usage Examples

### Get All Installed Updates
```powershell
Get-LocalUpdateStatus -ComputerName localhost -UpdateSearchFilter 'IsInstalled=1'
```

### Get Missing Updates
```powershell
Get-LocalUpdateStatus -ComputerName localhost -UpdateSearchFilter 'IsInstalled=0'
```

### Get Hidden Updates
```powershell
Get-LocalUpdateStatus -ComputerName localhost -UpdateSearchFilter 'IsHidden=1'
```

### Download Missing Updates
```powershell
# Download missing updates to default location (%TEMP%\WindowsUpdates)
Get-LocalUpdateStatus -ComputerName localhost -UpdateSearchFilter 'IsInstalled=0' -DownloadUpdates

# Download to custom location
Get-LocalUpdateStatus -ComputerName localhost -UpdateSearchFilter 'IsInstalled=0' -DownloadUpdates -DownloadPath "C:\Updates"

# Download only critical and important updates
Get-LocalUpdateStatus -ComputerName localhost -UpdateSearchFilter 'IsInstalled=0' -DownloadUpdates | 
    Where-Object { $_.SeverityText -in @('Critical', 'Important') }
```

### Download and Install Updates (NEW!)
```powershell
# Download and automatically install missing updates
Get-LocalUpdateStatus -ComputerName localhost -UpdateSearchFilter 'IsInstalled=0' -DownloadUpdates -InstallUpdates

# Download and install to custom location
Get-LocalUpdateStatus -ComputerName localhost -UpdateSearchFilter 'IsInstalled=0' -DownloadUpdates -InstallUpdates -DownloadPath "C:\Updates"

# Download and install only critical updates
Get-LocalUpdateStatus -ComputerName localhost -UpdateSearchFilter 'IsInstalled=0' -DownloadUpdates -InstallUpdates | 
    Where-Object { $_.SeverityText -eq 'Critical' }

# WSUS offline scan with download and installation
Get-LocalUpdateStatus -ComputerName localhost -WSUSOfflineScan -WSUSScanFile "C:\wsusscn2.cab" -UpdateSearchFilter 'IsInstalled=0' -DownloadUpdates -InstallUpdates
```

### Export/Import for Air-gapped Environments (NEW!)

#### Step 1: Export Scan Results (Machine without Internet)
```powershell
# Export missing updates scan to XML file
Get-LocalUpdateStatus -ComputerName localhost -UpdateSearchFilter 'IsInstalled=0' -ExportReport "C:\Reports\Server01_MissingUpdates"

# Export with timestamp in filename
Get-LocalUpdateStatus -ComputerName localhost -UpdateSearchFilter 'IsInstalled=0' -ExportReport "C:\Reports\$(Get-Date -Format 'yyyyMMdd')_Server01_Updates"

# Export all visible updates for comprehensive report
Get-LocalUpdateStatus -ComputerName localhost -UpdateSearchFilter 'IsHidden=0' -ExportReport "C:\Reports\Server01_AllUpdates"
```

#### Step 2: Import and Download (Machine with Internet)
```powershell
# Import scan results and download all available updates
Get-LocalUpdateStatus -ImportReport "C:\Reports\Server01_MissingUpdates.xml" -DownloadUpdates -DownloadPath "C:\UpdateFiles\Server01"

# Just view imported results without downloading
Get-LocalUpdateStatus -ImportReport "C:\Reports\Server01_MissingUpdates.xml"

# Import and download to default location
Get-LocalUpdateStatus -ImportReport "C:\Reports\Server01_MissingUpdates.xml" -DownloadUpdates

# Filter critical updates from imported data
Get-LocalUpdateStatus -ImportReport "C:\Reports\Server01_MissingUpdates.xml" | Where-Object { $_.SeverityText -eq 'Critical' }
```

### WSUS Offline Scanning (NEW!)

#### Download and Use Latest wsusscn2.cab
```powershell
# Download latest wsusscn2.cab and perform offline scan for missing updates
Get-LocalUpdateStatus -ComputerName localhost -WSUSOfflineScan -DownloadWSUSScanFile -UpdateSearchFilter 'IsInstalled=0'

# Download to custom location and scan for installed updates
Get-LocalUpdateStatus -ComputerName localhost -WSUSOfflineScan -DownloadWSUSScanFile -WSUSScanFileDownloadPath "C:\WSUS" -UpdateSearchFilter 'IsInstalled=1'

# Download, scan for hidden updates, and export results
Get-LocalUpdateStatus -ComputerName localhost -WSUSOfflineScan -DownloadWSUSScanFile -UpdateSearchFilter 'IsHidden=1' -ExportReport "C:\Reports\WSUS_HiddenUpdates"

# Download, scan for all visible updates, and export
Get-LocalUpdateStatus -ComputerName localhost -WSUSOfflineScan -DownloadWSUSScanFile -UpdateSearchFilter 'IsHidden=0' -ExportReport "C:\Reports\WSUS_AllVisible"
```

#### Use Existing wsusscn2.cab (Completely Offline)
```powershell
# Use existing wsusscn2.cab file for offline scan - missing updates
Get-LocalUpdateStatus -ComputerName localhost -WSUSOfflineScan -WSUSScanFile "C:\WSUS\wsusscn2.cab" -UpdateSearchFilter 'IsInstalled=0'

# Use relative path for scan file - installed updates
Get-LocalUpdateStatus -ComputerName localhost -WSUSOfflineScan -WSUSScanFile ".\wsusscn2.cab" -UpdateSearchFilter 'IsInstalled=1'

# Offline scan for visible missing updates with export
Get-LocalUpdateStatus -ComputerName localhost -WSUSOfflineScan -WSUSScanFile "C:\WSUS\wsusscn2.cab" -UpdateSearchFilter 'IsHidden=0 and IsInstalled=0' -ExportReport "C:\Reports\AirgappedServer_OfflineScan"

# Offline scan for hidden updates
Get-LocalUpdateStatus -ComputerName localhost -WSUSOfflineScan -WSUSScanFile ".\wsusscn2.cab" -UpdateSearchFilter 'IsHidden=1'

# Offline scan with download (requires internet for download phase)
Get-LocalUpdateStatus -ComputerName localhost -WSUSOfflineScan -WSUSScanFile "C:\WSUS\wsusscn2.cab" -UpdateSearchFilter 'IsInstalled=0' -DownloadUpdates -DownloadPath "C:\OfflineUpdates"
```
```

### Formatted Output Example
```powershell
Get-LocalUpdateStatus -ComputerName localhost -UpdateSearchFilter 'IsInstalled=1' | 
    Select-Object -Property KbId, IsInstalled, InstalledOn, Title, SeverityText | 
    Sort-Object -Property InstalledOn -Descending | 
    Format-Table -AutoSize
```

## Output Properties

Each update object contains the following properties:

| Property | Description |
|----------|-------------|
| `Computer` | Computer name |
| `Id` | Security bulletin ID |
| `CVEIds` | Common Vulnerabilities and Exposures IDs |
| `BulletinId` | Microsoft Security Bulletin ID |
| `KbId` | Microsoft Knowledge Base article ID |
| `Type` | Update type (Software, Driver, etc.) |
| `IsInstalled` | Installation status (True/False) |
| `InstalledOn` | Installation date and time |
| `RestartRequired` | Whether restart is required |
| `Title` | Update title/name |
| `Description` | Detailed update description |
| `SeverityText` | Security severity (Unspecified, Low, Moderate, Important, Critical) |
| `Severity` | Numeric severity value |
| `InformationURL` | Microsoft information URL |
| `SupportURL` | Support URL |
| `DownloadURL` | Download URL |
| `BulletinURL` | Security bulletin URL |
| `DownloadSuccess` | Download success status (only when `-DownloadUpdates` is used) |
| `ScanMethod` | Scan method used ("WSUS Offline" for offline scans, not present for normal scans) |

## Download Features

### Automatic File Download
When using the `-DownloadUpdates` switch, the script will:
- Create the download directory if it doesn't exist
- Download update files from Microsoft servers when DownloadURL is available
- Skip files that already exist in the download location
- Display download progress and file sizes
- Provide a comprehensive download summary

### Download Summary
After download completion, a summary is displayed showing:
- Total updates found
- Updates with available download URLs
- Number of successful downloads
- Download location path

### File Naming
Downloaded files are named using:
1. Original filename from the download URL (preferred)
2. Fallback format: `KB{KbId}.msu` if no filename is available

## Air-gapped Environment Workflow

The export/import functionality enables update management for machines without direct internet access:

### Scenario: Updating Air-gapped Servers

#### Phase 1: Scan and Export (On Target Machine)
1. **Scan the air-gapped machine:**
   ```powershell
   Get-LocalUpdateStatus -ComputerName localhost -UpdateSearchFilter 'IsInstalled=0' -ExportReport "C:\Temp\AirgappedServer_Updates"
   ```

2. **Transfer the export file** (`AirgappedServer_Updates.xml`) to an internet-connected machine via:
   - USB drive
   - Secure file transfer
   - Network share (if available)

#### Phase 2: Download Updates (On Internet-connected Machine)
3. **Download updates using the exported report:**
   ```powershell
   Get-LocalUpdateStatus -ImportReport "C:\Temp\AirgappedServer_Updates.xml" -DownloadUpdates -DownloadPath "C:\UpdateFiles\AirgappedServer"
   ```

4. **Review download results** and **transfer update files** back to the target machine

#### Phase 3: Install Updates (On Target Machine)
5. **Install the downloaded updates** using standard Windows update installation methods

### Enterprise Multi-Machine Example
```powershell
# Script to scan multiple servers and create individual export files
$servers = @("Server01", "Server02", "Server03")
foreach ($server in $servers) {
    Get-LocalUpdateStatus -ComputerName $server -UpdateSearchFilter 'IsInstalled=0' -ExportReport "C:\Reports\$server`_Updates_$(Get-Date -Format 'yyyyMMdd')"
}

# Later, on internet-connected machine, download for all servers
Get-ChildItem "C:\Reports\*_Updates_*.xml" | ForEach-Object {
    $serverName = ($_.BaseName -split '_')[0]
    Get-LocalUpdateStatus -ImportReport $_.FullName -DownloadUpdates -DownloadPath "C:\UpdateFiles\$serverName"
}
```

## WSUS Offline Scanning Workflow

The WSUS offline scan functionality uses Microsoft's official wsusscn2.cab file for completely offline update detection:

### Scenario 1: Completely Air-gapped Environment

#### Phase 1: Prepare wsusscn2.cab (On Internet-connected Machine)
1. **Download the latest wsusscn2.cab:**
   ```powershell
   Get-LocalUpdateStatus -ComputerName localhost -WSUSOfflineScan -DownloadWSUSScanFile -WSUSScanFileDownloadPath "C:\PortableWSUS"
   ```

2. **Transfer wsusscn2.cab** to the air-gapped machine via USB, secure transfer, etc.

#### Phase 2: Scan Air-gapped Machine (Completely Offline)
3. **Perform offline scan:**
   ```powershell
   # Scan for missing updates
   Get-LocalUpdateStatus -ComputerName localhost -WSUSOfflineScan -WSUSScanFile "C:\PortableWSUS\wsusscn2.cab" -UpdateSearchFilter 'IsInstalled=0' -ExportReport "C:\ScanResults\OfflineMissingScan"
   
   # Scan for installed updates
   Get-LocalUpdateStatus -ComputerName localhost -WSUSOfflineScan -WSUSScanFile "C:\PortableWSUS\wsusscn2.cab" -UpdateSearchFilter 'IsInstalled=1' -ExportReport "C:\ScanResults\OfflineInstalledScan"
   
   # Scan for hidden updates
   Get-LocalUpdateStatus -ComputerName localhost -WSUSOfflineScan -WSUSScanFile "C:\PortableWSUS\wsusscn2.cab" -UpdateSearchFilter 'IsHidden=1' -ExportReport "C:\ScanResults\OfflineHiddenScan"
   ```

4. **Transfer scan results** back to internet-connected machine

#### Phase 3: Download Updates (On Internet-connected Machine)
5. **Download missing updates:**
   ```powershell
   Get-LocalUpdateStatus -ImportReport "C:\ScanResults\OfflineMissingScan.xml" -DownloadUpdates -DownloadPath "C:\SecurityUpdates"
   ```

### Scenario 2: One-time Internet Access for Scan Setup

```powershell
# Download wsusscn2.cab, scan for missing updates immediately, and export for future use
Get-LocalUpdateStatus -ComputerName localhost -WSUSOfflineScan -DownloadWSUSScanFile -UpdateSearchFilter 'IsInstalled=0' -ExportReport "C:\Reports\CurrentMissingUpdates"

# Later, use the same wsusscn2.cab for other machines (offline) - scan for different criteria
Get-LocalUpdateStatus -ComputerName ServerB -WSUSOfflineScan -WSUSScanFile "$env:TEMP\wsusscn2.cab" -UpdateSearchFilter 'IsInstalled=1' -ExportReport "C:\Reports\ServerB_InstalledUpdates"

# Scan for hidden updates on another machine
Get-LocalUpdateStatus -ComputerName ServerC -WSUSOfflineScan -WSUSScanFile "$env:TEMP\wsusscn2.cab" -UpdateSearchFilter 'IsHidden=1' -ExportReport "C:\Reports\ServerC_HiddenUpdates"
```

### Enterprise Multi-Server WSUS Offline Scanning

```powershell
# Prepare wsusscn2.cab once
Get-LocalUpdateStatus -ComputerName localhost -WSUSOfflineScan -DownloadWSUSScanFile -WSUSScanFileDownloadPath "C:\Enterprise\WSUS"

# Scan multiple servers for different criteria using the same wsusscn2.cab
$servers = @("Server01", "Server02", "Server03", "Server04")

# Scan for missing updates
foreach ($server in $servers) {
    Get-LocalUpdateStatus -ComputerName $server -WSUSOfflineScan -WSUSScanFile "C:\Enterprise\WSUS\wsusscn2.cab" -UpdateSearchFilter 'IsInstalled=0' -ExportReport "C:\Reports\$server`_MissingUpdates_$(Get-Date -Format 'yyyyMMdd')"
}

# Scan for installed updates
foreach ($server in $servers) {
    Get-LocalUpdateStatus -ComputerName $server -WSUSOfflineScan -WSUSScanFile "C:\Enterprise\WSUS\wsusscn2.cab" -UpdateSearchFilter 'IsInstalled=1' -ExportReport "C:\Reports\$server`_InstalledUpdates_$(Get-Date -Format 'yyyyMMdd')"
}

# Scan for hidden updates
foreach ($server in $servers) {
    Get-LocalUpdateStatus -ComputerName $server -WSUSOfflineScan -WSUSScanFile "C:\Enterprise\WSUS\wsusscn2.cab" -UpdateSearchFilter 'IsHidden=1' -ExportReport "C:\Reports\$server`_HiddenUpdates_$(Get-Date -Format 'yyyyMMdd')"
}

# Bulk download missing updates for all servers
Get-ChildItem "C:\Reports\*_MissingUpdates_*.xml" | ForEach-Object {
    $serverName = ($_.BaseName -split '_')[0]
    Get-LocalUpdateStatus -ImportReport $_.FullName -DownloadUpdates -DownloadPath "C:\UpdateFiles\$serverName\MissingUpdates"
}
```

## Sample Output

```
KbId     IsInstalled InstalledOn          Title                                                     SeverityText
----     ----------- -----------          -----                                                     ------------
4577586  True        16.02.2021 00:00:00  Update für die Entfernung von Adobe Flash Player...      Unspecified
4023057  True        11.02.2021 00:00:00  2021-01 Update für Windows 10 Version 20H2...            Unspecified
4601050  True        09.02.2021 00:00:00  2021-02 Kumulatives Update für .NET Framework...         Important
4580325  True        20.10.2020 00:00:00  2020-10 Sicherheitsupdate für Adobe Flash Player...     Critical
```

## Sample Export Output

```
Windows Update is using Microsoft Update (default)

Processing updates...
Found 15 updates total

Report exported successfully to: C:\Reports\Server01_MissingUpdates.xml
Use this file with -ImportReport parameter on another machine to download updates
```

## Sample Import & Download Output

```
Import Report Mode: Loading update data from file...
Import file: C:\Reports\Server01_MissingUpdates.xml
Successfully loaded 15 updates from report

Download mode enabled for imported updates...
Created download directory: C:\UpdateFiles\Server01

Processing imported update: KB5001234 - 2025-10 Cumulative Update for Windows 10
  Downloading: windows10.0-kb5001234-x64_abc123.msu
  From: http://download.windowsupdate.com/c/msdownload/update/software/secu/2025/10/windows10.0-kb5001234-x64_abc123_def456.msu
  Downloaded successfully: windows10.0-kb5001234-x64_abc123.msu (45.67 MB)

Processing imported update: KB5002345 - Security Update for Windows Defender
  Downloading: KB5002345.msu
  From: http://download.windowsupdate.com/d/msdownload/update/software/secu/2025/10/kb5002345_xyz789.msu
  Downloaded successfully: KB5002345.msu (12.34 MB)

==================================================
IMPORT & DOWNLOAD SUMMARY
==================================================
Total updates imported: 15
Updates with download URLs: 12
Successful downloads: 11
Download location: C:\UpdateFiles\Server01
==================================================
```

## Sample WSUS Offline Scan Output

```
WSUS Offline Scan Mode: Scanning with wsusscn2.cab...
Downloading WSUS scan file from Microsoft...
URL: https://catalog.s.download.windowsupdate.com/microsoftupdate/v6/wsusscan/wsusscn2.cab
Destination: C:\WSUS\wsusscn2.cab
Downloaded successfully: wsusscn2.cab (145.23 MB)

Using WSUS scan file: C:\WSUS\wsusscn2.cab
Performing offline scan with filter: IsInstalled=0...
Found 23 updates via offline scan

==================================================
WSUS OFFLINE SCAN SUMMARY
==================================================
Scan file used: wsusscn2.cab
Search filter: IsInstalled=0
Total updates found: 23
Critical updates: 5
Important updates: 12
==================================================
```

## Sample WSUS Offline Scan with Different Filters

```
# Scanning for installed updates
WSUS Offline Scan Mode: Scanning with wsusscn2.cab...
Using WSUS scan file: C:\WSUS\wsusscn2.cab
Performing offline scan with filter: IsInstalled=1...
Found 156 updates via offline scan

==================================================
WSUS OFFLINE SCAN SUMMARY
==================================================
Scan file used: wsusscn2.cab
Search filter: IsInstalled=1
Total updates found: 156
Critical updates: 23
Important updates: 67
==================================================

# Scanning for hidden updates
WSUS Offline Scan Mode: Scanning with wsusscn2.cab...
Using WSUS scan file: C:\WSUS\wsusscn2.cab
Performing offline scan with filter: IsHidden=1...
Found 8 updates via offline scan

==================================================
WSUS OFFLINE SCAN SUMMARY
==================================================
Scan file used: wsusscn2.cab
Search filter: IsHidden=1
Total updates found: 8
Critical updates: 0
Important updates: 3
==================================================
```

## Sample WSUS Offline Scan with Download

```
WSUS Offline Scan Mode: Scanning with wsusscn2.cab...
Using WSUS scan file: C:\WSUS\wsusscn2.cab
Performing offline scan with filter: IsInstalled=0...
Found 23 updates via offline scan

Processing update: KB5001234 - 2025-10 Security Update for Windows 10
  Downloading: windows10.0-kb5001234-x64_security.msu
  From: http://download.windowsupdate.com/c/msdownload/update/software/secu/2025/10/windows10.0-kb5001234-x64_security_abc123.msu
  Downloaded successfully: windows10.0-kb5001234-x64_security.msu (67.89 MB)

Processing update: KB5002345 - Security Update for Windows Defender
  Downloading: KB5002345.msu
  From: http://download.windowsupdate.com/d/msdownload/update/software/secu/2025/10/kb5002345_defender_xyz789.msu
  Downloaded successfully: KB5002345.msu (23.45 MB)

==================================================
WSUS OFFLINE SCAN SUMMARY
==================================================
Scan file used: wsusscn2.cab
Search filter: IsInstalled=0
Total updates found: 23
Critical updates: 5
Important updates: 12
Updates with download URLs: 20
Successful downloads: 19
Download location: C:\OfflineUpdates
==================================================
```

## Sample Output with Manual Download Guidance

```
Update KB5070884 has no direct download URL available
  Title: 2025-10 Cumulative Update for Microsoft server operating system version 21H2 for x64-based Systems (KB5070884)
  Manual download available at: https://www.catalog.update.microsoft.com/Search.aspx?q=KB5070884
  Alternative: Use Windows Update, WSUS, or Microsoft Update Catalog

==================================================
DOWNLOAD SUMMARY
==================================================
Total updates found: 15
Updates with download URLs: 8
Updates requiring manual download: 7
Successful downloads: 6
Download location: C:\Temp\WindowsUpdates

Updates requiring manual download:
  - KB5070884: 2025-10 Cumulative Update for Microsoft server operating system version 21H2 for x64-based Systems (KB5070884)
    Download: https://www.catalog.update.microsoft.com/Search.aspx?q=KB5070884
  - KB5070123: Security Update for Windows Server 2022 (KB5070123)
    Download: https://www.catalog.update.microsoft.com/Search.aspx?q=KB5070123

Tip: Visit Microsoft Update Catalog for manual downloads
==================================================
```

## Sample Object Properties with Manual Download Information

```powershell
Computer              : AO-PKI
KbId                  : 5070884
Title                 : 2025-10 Cumulative Update for Microsoft server operating system version 21H2 for x64-based Systems (KB5070884)
IsInstalled           : False
DownloadURL           : 
ManualDownloadInfo    : No direct download URL available. Manual download: Microsoft Update Catalog
MicrosoftCatalogURL   : https://www.catalog.update.microsoft.com/Search.aspx?q=KB5070884
DownloadNote          : No direct URL - manual download required
InformationURL        : https://support.microsoft.com/help/5070884
SupportURL            : https://support.microsoft.com/help/5070884
```

## Sample Installation Output

```
Processing update: KB5001234 - 2025-10 Cumulative Update for Windows 10
  Downloading: windows10.0-kb5001234-x64_abc123.msu
  From: http://download.windowsupdate.com/c/msdownload/update/software/secu/2025/10/windows10.0-kb5001234-x64_abc123_def456.msu
  Downloaded successfully: windows10.0-kb5001234-x64_abc123.msu (45.67 MB)
  Installing: windows10.0-kb5001234-x64_abc123.msu
  Using WUSA for .msu installation...
  Installation successful: windows10.0-kb5001234-x64_abc123.msu

Processing update: KB5002345 - Security Update for Windows 10
  Downloading: windows10.0-kb5002345-x64_def789.cab
  From: http://download.windowsupdate.com/d/msdownload/update/software/secu/2025/10/windows10.0-kb5002345-x64_def789.cab
  Downloaded successfully: windows10.0-kb5002345-x64_def789.cab (12.34 MB)
  Installing: windows10.0-kb5002345-x64_def789.cab
  Using DISM for .cab installation...
  Installation successful: windows10.0-kb5002345-x64_def789.cab

==================================================
DOWNLOAD & INSTALLATION SUMMARY
==================================================
Total updates found: 15
Updates with download URLs: 8
Updates requiring manual download: 7
Successful downloads: 6
Successful installations: 6
Download location: C:\Temp\WindowsUpdates
==================================================
```

## Sample Object Properties with Installation Information

```powershell
Computer              : MYSERVER
KbId                  : 5001234
Title                 : 2025-10 Cumulative Update for Windows 10
IsInstalled           : False
DownloadURL           : http://download.windowsupdate.com/c/msdownload/update/...
DownloadSuccess       : True
InstallSuccess        : True
InstalledFilePath     : C:\Temp\WindowsUpdates\windows10.0-kb5001234-x64_abc123.msu
ManualDownloadInfo    : 
MicrosoftCatalogURL   : 
```

## Sample Download Output

```
Windows Update is using Microsoft Update (default)

Created download directory: C:\Temp\WindowsUpdates

Processing update: KB5001234 - 2025-10 Cumulative Update for Windows 10
  Downloading: windows10.0-kb5001234-x64_abc123.msu
  From: http://download.windowsupdate.com/c/msdownload/update/software/secu/2025/10/windows10.0-kb5001234-x64_abc123_def456.msu
  Downloaded successfully: windows10.0-kb5001234-x64_abc123.msu (45.67 MB)

==================================================
DOWNLOAD SUMMARY
==================================================
Total updates found: 15
Updates with download URLs: 8
Successful downloads: 7
Download location: C:\Temp\WindowsUpdates
==================================================
```

## Update Source Detection

The script automatically detects and displays the Windows Update source:
- **WSUS (Windows Server Update Services)** - If configured via Group Policy
- **Microsoft Update** - Default source for most systems

## Version Information

- **Version:** 1.4.0
- **Author:** Jan Tiedemann
- **Copyright:** 2021-2025
- **GUID:** 4b937790-b06b-427f-8c1f-565030ae0227
- **Last Updated:** October 2025

### Recent Updates (v1.4.0)
- **NEW: Automatic update installation with `-InstallUpdates` parameter**
- **Support for .cab files** via DISM.exe (/Online /Add-Package /Quiet /NoRestart)
- **Support for .msu files** via wusa.exe (/quiet /norestart)
- **Enhanced result objects** with InstallSuccess and InstalledFilePath properties
- **Improved summaries** showing installation statistics
- **Automatic file type detection** and appropriate installer selection
- **Comprehensive error handling** for installation failures
- **NEW: Manual download guidance for updates without direct URLs**
- Added `ManualDownloadInfo` and `MicrosoftCatalogURL` properties to update objects
- Enhanced download summaries to show updates requiring manual download
- **FIXED: WSUS offline scan now working correctly with wsusscn2.cab**

## Quick Reference

### Most Common Commands

```powershell
# Basic scan for missing updates
Get-LocalUpdateStatus -UpdateSearchFilter "IsInstalled=0"

# Scan and download missing updates
Get-LocalUpdateStatus -UpdateSearchFilter "IsInstalled=0" -DownloadUpdates -DownloadPath "C:\Temp"

# WSUS offline scan (run as Administrator)
Get-LocalUpdateStatus -WSUSOfflineScan -WSUSScanFile "C:\Path\To\wsusscn2.cab" -UpdateSearchFilter "IsInstalled=0"

# Export scan results for air-gapped systems
Get-LocalUpdateStatus -UpdateSearchFilter "IsInstalled=0" -ExportReport "C:\Temp\UpdateReport"

# Import and process exported results
Get-LocalUpdateStatus -ImportReport "C:\Temp\UpdateReport.xml" -DownloadUpdates -DownloadPath "C:\Updates"
```

### Quick Troubleshooting Checklist

1. ✅ **Run PowerShell as Administrator**
2. ✅ **Use absolute paths for wsusscn2.cab file**
3. ✅ **Verify wsusscn2.cab file is valid (100-200MB)**
4. ✅ **Check Windows Update service is running**
5. ✅ **Ensure internet connectivity for downloads**

## Notes

### General Requirements
- Run PowerShell as Administrator for proper execution
- For remote computers, ensure WinRM is configured and you have administrative access
- The script uses the Microsoft Update Session COM object for update enumeration
- Large numbers of updates may take time to process

### Download Features
- **Download feature requires internet access to Microsoft Update servers**
- **Downloaded files are standard .msu or .cab files that can be installed manually**
- **Always verify downloaded files before installation**

### Installation Features
- **InstallUpdates requires DownloadUpdates to be enabled**
- **Automatic file type detection** (.cab uses DISM, .msu uses WUSA)
- **Silent installation** with /Quiet /NoRestart and /quiet /norestart flags
- **No automatic restart** - manual restart required if needed
- **Installation status tracking** in InstallSuccess property
- **Supports error handling** with proper exit code interpretation
- **Administrator privileges required** for installation operations
- **Compatible with all scan modes** (online, offline, import)

### Export/Import Features
- **Export files use PowerShell XML serialization format (.xml)**
- **Export files contain complete update metadata including download URLs**
- **Import mode works independently of internet connectivity**
- **Perfect for air-gapped, DMZ, or security-restricted environments**
- **Export files are portable between different Windows systems**

### WSUS Offline Scan Features
- **Uses Microsoft's official wsusscn2.cab file for offline scanning**
- **Provides completely offline update detection capability**
- **Supports all filter options** (missing, installed, hidden, visible updates)
- **Supports both relative and absolute file paths** for wsusscn2.cab
- **Automatic path resolution** for relative paths to work with COM objects
- **wsusscn2.cab is regularly updated by Microsoft with latest security definitions**
- **Perfect for high-security, completely air-gapped environments**
- **Can detect any update type without any network connectivity**
- **Compatible with all other features (export, download, etc.)**
- **wsusscn2.cab file size is typically 100-200 MB**
- **Enhanced SSL/TLS handling** for reliable downloads from Microsoft servers

### Manual Download Support
- **Automatic detection of updates without direct download URLs**
- **Microsoft Update Catalog URLs** automatically generated for KB articles  
- **Detailed manual download guidance** in console output and summary reports
- **Enhanced download summaries** showing which updates require manual download
- **Perfect for cumulative updates** that often lack direct download URLs
- **Clear instructions** for using Microsoft Update Catalog or Windows Update

### Automatic Installation Support
- **Automatic installation** of downloaded updates with `-InstallUpdates` parameter
- **DISM integration** for .cab file installation with silent operation
- **WUSA integration** for .msu file installation with silent operation  
- **No restart requirement** - installations use /NoRestart and /norestart flags
- **Comprehensive error handling** with proper exit code interpretation
- **Installation status tracking** in result objects (InstallSuccess property)
- **File path tracking** for installed updates (InstalledFilePath property)
- **Supports both online and offline scan modes** with installation capability

## Troubleshooting

### Common Issues and Solutions

#### WSUS Offline Scan Returns 0 Updates

**Problem:** WSUS offline scan shows "Found 0 updates" even when updates should be available.

**Status:** ✅ **FIXED in v1.3.2** - The main COM object implementation issue has been resolved.

**If you still experience issues, check these common causes:**

1. **Administrator Rights Required**
   ```
   Error: "This script needs to be run As Admin"
   ```
   - **Solution:** Run PowerShell as Administrator
   - Right-click PowerShell and select "Run as Administrator"

2. **Invalid or Corrupted wsusscn2.cab File**
   - **Solution:** Download a fresh copy of wsusscn2.cab from Microsoft
   ```powershell
   # Use the built-in download feature
   Get-LocalUpdateStatus -WSUSOfflineScan -DownloadWSUSScanFile -WSUSScanFileDownloadPath C:\Temp
   ```

3. **File Path Issues**
   - **Problem:** Relative paths may not work correctly with COM objects
   - **Solution:** Use absolute paths for wsusscn2.cab
   ```powershell
   # Instead of: .\wsusscn2.cab
   # Use: C:\Full\Path\To\wsusscn2.cab
   Get-LocalUpdateStatus -WSUSOfflineScan -WSUSScanFile "C:\Users\Administrator\Downloads\wsusscn2.cab"
   ```

4. **Outdated wsusscn2.cab File**
   - **Problem:** Old scan file may not contain recent update definitions
   - **Solution:** Download the latest wsusscn2.cab from Microsoft (typically 100-200MB)
   - The scan file is regularly updated by Microsoft with new security definitions

5. **COM Object Registration Issues**
   - **Solution:** Try running Windows Update troubleshooter or restart Windows Update service
   ```powershell
   Stop-Service wuauserv
   Start-Service wuauserv
   ```

#### Download Issues

**Problem:** SSL/TLS errors when downloading updates or wsusscn2.cab

**Solutions:**
- The script includes enhanced SSL/TLS handling with automatic protocol fallback
- Ensure Windows is updated with latest security protocols
- Check corporate firewall/proxy settings

#### Permission Issues

**Problem:** Access denied errors when creating directories or writing files

**Solutions:**
- Run PowerShell as Administrator
- Ensure write permissions to download/export directories
- Use locations where the user has full control (e.g., C:\Temp instead of system directories)

#### Remote Computer Access

**Problem:** Cannot connect to remote computers

**Solutions:**
- Ensure WinRM is enabled: `Enable-PSRemoting -Force`
- Verify firewall settings allow WinRM traffic
- Confirm administrative access to target computers
- Test connectivity: `Test-WSMan -ComputerName TargetServer`

### Debug Testing

If WSUS offline scan continues to return 0 updates, use the included test script:

```powershell
.\Test-WSUSOfflineScan.ps1 -WSUSScanFile "C:\Path\To\wsusscn2.cab" -UpdateSearchFilter "IsInstalled=0"
```

This test script provides detailed debug output to help identify the specific issue.

### Known Limitations

- **WSUS offline scan requires the exact Microsoft wsusscn2.cab file format**
- **Large wsusscn2.cab files (>100MB) may take several minutes to process**
- **Some corporate environments may block COM object access for security**
- **Remote WSUS offline scanning is not supported (file must be local)**
