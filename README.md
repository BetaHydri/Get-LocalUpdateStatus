# Get-LocalUpdateStatus

A PowerShell function that enumerates Windows Updates (both installed and missing) on local or remote computers and returns detailed update information as PowerShell objects. **Now includes the ability to download update files directly from Microsoft and support for air-gapped environments through export/import functionality!**

## Description

This script provides detailed information about Windows Updates including:
- Installed updates
- Missing/available updates  
- Hidden updates
- Update metadata (KB IDs, security bulletins, CVE IDs, severity, etc.)
- Installation dates and restart requirements
- **NEW: Direct download capability for updates with available download URLs**
- **NEW: Export/Import functionality for air-gapped or restricted network environments**

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

### DownloadPath (Optional)
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

### Download Missing Updates (NEW!)
```powershell
# Download missing updates to default location (%TEMP%\WindowsUpdates)
Get-LocalUpdateStatus -ComputerName localhost -UpdateSearchFilter 'IsInstalled=0' -DownloadUpdates

# Download to custom location
Get-LocalUpdateStatus -ComputerName localhost -UpdateSearchFilter 'IsInstalled=0' -DownloadUpdates -DownloadPath "C:\Updates"

# Download only critical and important updates
Get-LocalUpdateStatus -ComputerName localhost -UpdateSearchFilter 'IsInstalled=0' -DownloadUpdates | 
    Where-Object { $_.SeverityText -in @('Critical', 'Important') }
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

- **Version:** 1.2.0
- **Author:** Jan Tiedemann
- **Copyright:** 2021
- **GUID:** 4b937790-b06b-427f-8c1f-565030ae0227

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

### Export/Import Features
- **Export files use PowerShell XML serialization format (.xml)**
- **Export files contain complete update metadata including download URLs**
- **Import mode works independently of internet connectivity**
- **Perfect for air-gapped, DMZ, or security-restricted environments**
- **Export files are portable between different Windows systems**
- **Download feature requires internet access to Microsoft Update servers**
- **Downloaded files are standard .msu or .cab files that can be installed manually**
- **Always verify downloaded files before installation**
