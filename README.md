# Get-LocalUpdateStatus

A PowerShell function for comprehensive Windows Update management on local computers. Features batch download-first-then-install workflow, WSUS offline scanning, and export/import functionality for air-gapped environments.

## Overview

Get-LocalUpdateStatus provides a complete solution for Windows Update management with three main operation modes:

- **Local Scanning**: Direct Windows Update scanning on the current computer
- **WSUS Offline Scanning**: Completely offline update detection using wsusscn2.cab  
- **Import Mode**: Process previously exported scan results for air-gapped workflows

## Key Features

✅ **Local-only operation** - runs directly on the computer to be scanned  
✅ **Batch download-first-then-install workflow** with interactive confirmation  
✅ **Multiple file format support**: .cab (DISM), .msu (WUSA), .exe (silent execution)  
✅ **WSUS offline scanning** using Microsoft's wsusscn2.cab for air-gapped environments  
✅ **Export/Import functionality** for transferring scan data between machines  
✅ **Intelligent .exe handling** with automatic silent switch detection  
✅ **Comprehensive progress visualization** and detailed batch processing summaries  

## Requirements

- **PowerShell 4.0** or higher
- **Administrator privileges** required
- **Local execution only** - script must be run directly on each computer to be scanned
- Uses Microsoft Update Session COM objects

## Installation

1. Download the `Get-LocalUpdateStatus.ps1` file
2. Import the script:
   ```powershell
   . .\Get-LocalUpdateStatus.ps1
   ```

## Parameters

### UpdateSearchFilter (Required)
Search filter for Windows Updates. Valid values:
- `'IsInstalled=0'` - Missing updates
- `'IsInstalled=1'` - Installed updates  
- `'IsHidden=0'` - Visible updates
- `'IsHidden=1'` - Hidden updates
- `'IsHidden=0 and IsInstalled=0'` - Visible missing updates
- `'IsHidden=0 and IsInstalled=1'` - Visible installed updates

### DownloadUpdates (Optional)
Enable automatic download of update files when download URLs are available.

### InstallUpdates (Optional)
Automatically install downloaded updates in batch mode. Requires `-DownloadUpdates`.

### DownloadPath (Optional)
Directory path for downloaded files. Default: `$env:TEMP\WindowsUpdates`

### ExportReport (Optional)
Export scan results to XML file for later import on another machine.

### ImportReport (Required for Import Mode)
Import previously exported XML report for processing.

### WSUSOfflineScan (Required for WSUS Offline Mode)
Enable WSUS offline scanning using wsusscn2.cab file.

### WSUSScanFile (Optional for WSUS Offline Mode)
**Smart parameter that accepts:**
- **Existing .cab file path**: Uses the file directly for scanning
- **Directory path**: Downloads latest wsusscn2.cab to this location
- **Not specified**: Downloads to `$env:TEMP` by default

**Examples:**
- `"C:\WSUS\wsusscn2.cab"` - Use existing file
- `"C:\WSUS"` - Download wsusscn2.cab to C:\WSUS directory
- Not specified - Download to temp directory

## Usage Examples

### Basic Scanning

```powershell
# Get all missing updates
Get-LocalUpdateStatus -UpdateSearchFilter 'IsInstalled=0'

# Get all installed updates  
Get-LocalUpdateStatus -UpdateSearchFilter 'IsInstalled=1'

# Get visible missing updates
Get-LocalUpdateStatus -UpdateSearchFilter 'IsHidden=0 and IsInstalled=0'

# Get hidden updates
Get-LocalUpdateStatus -UpdateSearchFilter 'IsHidden=1'
```

### Download Only (No Installation)

```powershell
# Download missing updates to default location
Get-LocalUpdateStatus -UpdateSearchFilter 'IsInstalled=0' -DownloadUpdates

# Download to custom location
Get-LocalUpdateStatus -UpdateSearchFilter 'IsInstalled=0' -DownloadUpdates -DownloadPath "C:\Updates"

# Download visible missing updates
Get-LocalUpdateStatus -UpdateSearchFilter 'IsHidden=0 and IsInstalled=0' -DownloadUpdates -DownloadPath "C:\SecurityUpdates"
```

### Download and Install (Batch Mode)

```powershell
# Download and install all missing updates
Get-LocalUpdateStatus -UpdateSearchFilter 'IsInstalled=0' -DownloadUpdates -InstallUpdates

# Download and install with custom path
Get-LocalUpdateStatus -UpdateSearchFilter 'IsInstalled=0' -DownloadUpdates -InstallUpdates -DownloadPath "C:\Updates"

# Download and install visible missing updates
Get-LocalUpdateStatus -UpdateSearchFilter 'IsHidden=0 and IsInstalled=0' -DownloadUpdates -InstallUpdates
```

### WSUS Offline Scanning

#### Download and Use Latest wsusscn2.cab

```powershell
# Download wsusscn2.cab to temp directory and scan for missing updates
Get-LocalUpdateStatus -WSUSOfflineScan -UpdateSearchFilter 'IsInstalled=0'

# Download wsusscn2.cab to custom location and scan
Get-LocalUpdateStatus -WSUSOfflineScan -WSUSScanFile "C:\WSUS" -UpdateSearchFilter 'IsInstalled=0'

# Download wsusscn2.cab, scan, and download updates
Get-LocalUpdateStatus -WSUSOfflineScan -UpdateSearchFilter 'IsInstalled=0' -DownloadUpdates

# Download wsusscn2.cab, scan, download and install updates
Get-LocalUpdateStatus -WSUSOfflineScan -UpdateSearchFilter 'IsInstalled=0' -DownloadUpdates -InstallUpdates
```

#### Use Existing wsusscn2.cab (Completely Offline)

```powershell
# Scan for missing updates using existing wsusscn2.cab
Get-LocalUpdateStatus -WSUSOfflineScan -WSUSScanFile "C:\WSUS\wsusscn2.cab" -UpdateSearchFilter 'IsInstalled=0'

# Scan for installed updates
Get-LocalUpdateStatus -WSUSOfflineScan -WSUSScanFile "C:\WSUS\wsusscn2.cab" -UpdateSearchFilter 'IsInstalled=1'

# Scan for hidden updates
Get-LocalUpdateStatus -WSUSOfflineScan -WSUSScanFile "C:\WSUS\wsusscn2.cab" -UpdateSearchFilter 'IsHidden=1'

# Offline scan with download (requires internet for download phase)
Get-LocalUpdateStatus -WSUSOfflineScan -WSUSScanFile "C:\WSUS\wsusscn2.cab" -UpdateSearchFilter 'IsInstalled=0' -DownloadUpdates -DownloadPath "C:\OfflineUpdates"

# Complete offline workflow with installation
Get-LocalUpdateStatus -WSUSOfflineScan -WSUSScanFile "C:\WSUS\wsusscn2.cab" -UpdateSearchFilter 'IsInstalled=0' -DownloadUpdates -InstallUpdates
```

### Export/Import for Air-Gapped Environments

#### Step 1: Export Scan Results (On Target Machine)

```powershell
# Export missing updates scan
Get-LocalUpdateStatus -UpdateSearchFilter 'IsInstalled=0' -ExportReport "C:\Reports\MissingUpdates"

# Export installed updates scan
Get-LocalUpdateStatus -UpdateSearchFilter 'IsInstalled=1' -ExportReport "C:\Reports\InstalledUpdates"

# Export with timestamp
Get-LocalUpdateStatus -UpdateSearchFilter 'IsInstalled=0' -ExportReport "C:\Reports\Updates_$(Get-Date -Format 'yyyyMMdd')"

# Export WSUS offline scan results
Get-LocalUpdateStatus -WSUSOfflineScan -WSUSScanFile "C:\wsusscn2.cab" -UpdateSearchFilter 'IsInstalled=0' -ExportReport "C:\Reports\OfflineUpdates"
```

#### Step 2: Import and Download (On Internet-Connected Machine)

```powershell
# Import and view results only
Get-LocalUpdateStatus -ImportReport "C:\Reports\MissingUpdates.xml"

# Import and download updates
Get-LocalUpdateStatus -ImportReport "C:\Reports\MissingUpdates.xml" -DownloadUpdates

# Import, download to custom location
Get-LocalUpdateStatus -ImportReport "C:\Reports\MissingUpdates.xml" -DownloadUpdates -DownloadPath "C:\UpdateFiles\Server01"

# Import, download and prepare for installation
Get-LocalUpdateStatus -ImportReport "C:\Reports\MissingUpdates.xml" -DownloadUpdates -InstallUpdates -DownloadPath "C:\UpdateFiles\Server01"
```

### Export Report with Different Filters

```powershell
# Export all visible updates
Get-LocalUpdateStatus -UpdateSearchFilter 'IsHidden=0' -ExportReport "C:\Reports\AllVisible"

# Export hidden updates
Get-LocalUpdateStatus -UpdateSearchFilter 'IsHidden=1' -ExportReport "C:\Reports\Hidden"

# Export visible missing updates
Get-LocalUpdateStatus -UpdateSearchFilter 'IsHidden=0 and IsInstalled=0' -ExportReport "C:\Reports\VisibleMissing"

# Export visible installed updates  
Get-LocalUpdateStatus -UpdateSearchFilter 'IsHidden=0 and IsInstalled=1' -ExportReport "C:\Reports\VisibleInstalled"
```

## Multi-Machine Management Workflow

For managing multiple servers or air-gapped environments:

### Phase 1: Local Scanning (Run on Each Server)

```powershell
# On Server01
Get-LocalUpdateStatus -UpdateSearchFilter 'IsInstalled=0' -ExportReport "C:\Temp\Server01_MissingUpdates"

# On Server02  
Get-LocalUpdateStatus -UpdateSearchFilter 'IsInstalled=0' -ExportReport "C:\Temp\Server02_MissingUpdates"

# On Server03
Get-LocalUpdateStatus -UpdateSearchFilter 'IsInstalled=0' -ExportReport "C:\Temp\Server03_MissingUpdates"
```

### Phase 2: Centralized Download (Internet-Connected Machine)

```powershell
# Download updates for all servers
Get-LocalUpdateStatus -ImportReport "C:\Reports\Server01_MissingUpdates.xml" -DownloadUpdates -DownloadPath "C:\UpdateFiles\Server01"
Get-LocalUpdateStatus -ImportReport "C:\Reports\Server02_MissingUpdates.xml" -DownloadUpdates -DownloadPath "C:\UpdateFiles\Server02"  
Get-LocalUpdateStatus -ImportReport "C:\Reports\Server03_MissingUpdates.xml" -DownloadUpdates -DownloadPath "C:\UpdateFiles\Server03"

# Bulk processing
Get-ChildItem "C:\Reports\*_MissingUpdates.xml" | ForEach-Object {
    $serverName = ($_.BaseName -split '_')[0]
    Get-LocalUpdateStatus -ImportReport $_.FullName -DownloadUpdates -DownloadPath "C:\UpdateFiles\$serverName"
}
```

### Phase 3: Transfer and Install (Back on Target Servers)

Transfer the downloaded update files to each server and install manually or use the script's installation features.

## Complete Air-Gapped Workflow with WSUS Offline

### Step 1: Prepare wsusscn2.cab (Internet-Connected Machine)

```powershell
# Download latest wsusscn2.cab to portable location
Get-LocalUpdateStatus -WSUSOfflineScan -WSUSScanFile "C:\Portable" -UpdateSearchFilter 'IsInstalled=0'
```

### Step 2: Offline Scanning (Air-Gapped Machine)

```powershell
# Scan for missing updates and export
Get-LocalUpdateStatus -WSUSOfflineScan -WSUSScanFile "C:\Portable\wsusscn2.cab" -UpdateSearchFilter 'IsInstalled=0' -ExportReport "C:\Results\OfflineScan_Missing"

# Scan for installed updates and export
Get-LocalUpdateStatus -WSUSOfflineScan -WSUSScanFile "C:\Portable\wsusscn2.cab" -UpdateSearchFilter 'IsInstalled=1' -ExportReport "C:\Results\OfflineScan_Installed"
```

### Step 3: Download Updates (Internet-Connected Machine)

```powershell
# Import offline scan results and download
Get-LocalUpdateStatus -ImportReport "C:\Results\OfflineScan_Missing.xml" -DownloadUpdates -DownloadPath "C:\AirGappedUpdates"
```

## Sample Output

### Basic Scan Output
```
Computer              : MYSERVER
KbId                  : 5034441  
Title                 : 2025-10 Security Update for Windows 10
IsInstalled           : False
SeverityText          : Critical
DownloadURL           : https://catalog.s.download...
```

### Download Phase Output
```
============================================================
STARTING BATCH DOWNLOAD PHASE
============================================================
Updates to download: 3
Download directory: C:\Temp\WindowsUpdates
============================================================

[1/3] Downloading KB5034441
  Title: 2025-10 Security Update for Windows 10
  File: KB5034441.msu
  Status: Download completed successfully
  Size: 67.8 MB
  Time: 02:15 (30.1 MB/s)

============================================================
DOWNLOAD PHASE COMPLETED
============================================================
Successful downloads: 3
Failed downloads: 0
Total downloaded: 103.9 MB
============================================================
```

### Installation Phase Output
```
WARNING: About to install 3 Windows Update(s)
This may require system restart(s) and could take significant time.
Do you want to proceed with installation? (Y/N): Y

============================================================
STARTING BATCH INSTALLATION
============================================================

[1/3] Installing KB5034441
  Title: 2025-10 Security Update for Windows 10
  File: KB5034441.msu
  Using WUSA for .msu installation...
  Status: Installation completed successfully
  Duration: 03:12

============================================================
BATCH INSTALLATION COMPLETED
============================================================
Total updates processed: 3
Successful installations: 3
Failed installations: 0
Success rate: 100.0%

Recommendation: Restart the computer to complete installation
============================================================
```

## Supported File Types

- **.cab files**: Installed via DISM with `/Online /Add-Package /Quiet /NoRestart`
- **.msu files**: Installed via WUSA with `/quiet /norestart`
- **.exe files**: Installed with intelligent silent switches:
  - **Malicious Software Removal Tool**: Uses `/Q`
  - **Windows Defender/Antimalware**: Uses `/q`
  - **Generic Microsoft executables**: Uses `/quiet`

## Quick Reference

```powershell
# Most common operations:

# Scan for missing updates
Get-LocalUpdateStatus -UpdateSearchFilter 'IsInstalled=0'

# Download missing updates  
Get-LocalUpdateStatus -UpdateSearchFilter 'IsInstalled=0' -DownloadUpdates

# Download and install missing updates
Get-LocalUpdateStatus -UpdateSearchFilter 'IsInstalled=0' -DownloadUpdates -InstallUpdates

# WSUS offline scan
Get-LocalUpdateStatus -WSUSOfflineScan -UpdateSearchFilter 'IsInstalled=0'

# Export for air-gapped transfer
Get-LocalUpdateStatus -UpdateSearchFilter 'IsInstalled=0' -ExportReport "Updates"

# Import and download
Get-LocalUpdateStatus -ImportReport "Updates.xml" -DownloadUpdates
```

## Troubleshooting

### No Updates Found
When scanning returns zero results for missing updates:
- **Good news!** Your system is up to date
- Script shows: "No missing updates found - system appears to be up to date!"

### WSUS Offline Compound Filter Issues
If you encounter errors with filters like `'IsHidden=0 and IsInstalled=0'` in offline mode:
- Use simplified filter: `'IsInstalled=0'`
- Compound filters may not be fully supported in WSUS offline mode

### Permission Issues
- Run PowerShell as Administrator
- Ensure write permissions to download directories
- Some corporate environments may block COM object access

### Multi-Machine Management
- Use export/import workflow for air-gapped environments
- For remote execution, use PowerShell remoting:
  ```powershell
  Invoke-Command -ComputerName Server01 -ScriptBlock {
      Get-LocalUpdateStatus -UpdateSearchFilter 'IsInstalled=0' -ExportReport "C:\Temp\Updates.xml"
  }
  ```

## Version Information

- **Version:** 1.6.0
- **Author:** Jan Tiedemann  
- **Copyright:** 2021-2025
- **Requirements:** PowerShell 4.0+, Administrator privileges
- **Operation:** Local computer only

---

*For additional support or feature requests, please refer to the project repository.*
