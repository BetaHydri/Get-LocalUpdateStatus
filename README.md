# Get-LocalUpdateStatus

A PowerShell function that enumerates Windows Updates (both installed and missing) on local or remote computers and returns detailed update information as PowerShell objects. **Now includes the ability to download update files directly from Microsoft!**

## Description

This script provides detailed information about Windows Updates including:
- Installed updates
- Missing/available updates  
- Hidden updates
- Update metadata (KB IDs, security bulletins, CVE IDs, severity, etc.)
- Installation dates and restart requirements
- **NEW: Direct download capability for updates with available download URLs**

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

## Sample Output

```
KbId     IsInstalled InstalledOn          Title                                                     SeverityText
----     ----------- -----------          -----                                                     ------------
4577586  True        16.02.2021 00:00:00  Update für die Entfernung von Adobe Flash Player...      Unspecified
4023057  True        11.02.2021 00:00:00  2021-01 Update für Windows 10 Version 20H2...            Unspecified
4601050  True        09.02.2021 00:00:00  2021-02 Kumulatives Update für .NET Framework...         Important
4580325  True        20.10.2020 00:00:00  2020-10 Sicherheitsupdate für Adobe Flash Player...     Critical
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

- **Version:** 1.1.0
- **Author:** Jan Tiedemann
- **Copyright:** 2021
- **GUID:** 4b937790-b06b-427f-8c1f-565030ae0227

## Notes

- Run PowerShell as Administrator for proper execution
- For remote computers, ensure WinRM is configured and you have administrative access
- The script uses the Microsoft Update Session COM object for update enumeration
- Large numbers of updates may take time to process
- **Download feature requires internet access to Microsoft Update servers**
- **Downloaded files are standard .msu or .cab files that can be installed manually**
- **Always verify downloaded files before installation**
