<#
PSScriptInfo

.VERSION 1.5.0

.GUID 4b937790-b06b-427f-8c1f-565030ae0227

.AUTHOR Jan Tiedemann

.COMPANYNAME Jan Tiedemann

.COPYRIGHT 2025

.TAGS Updates, WindowsUpdates, Download, Export, Import, WSUS, Offline, BatchInstall

.DESCRIPTION 
Enumerates missing or installed Windows Updates and returns an array of objects with update details. 
Features enhanced batch download-first-then-install workflow with comprehensive progress visualization.
Supports exporting scan results and importing them on other machines for download.
Supports WSUS offline scanning using wsusscn2.cab for air-gapped environments.
Includes interactive installation confirmation and detailed batch processing summaries.
#>

# Helper function to install updates
function Invoke-UpdateInstallation {
  param(
    [string]$FilePath,
    [string]$KbId,
    [string]$Title
  )
  
  if (-not (Test-Path $FilePath)) {
    Write-Host "  Installation failed: File not found - $FilePath" -ForegroundColor Red
    return $false
  }

  $fileExtension = [System.IO.Path]::GetExtension($FilePath).ToLower()
  $fileName = Split-Path $FilePath -Leaf
  
  Write-Host "  Installing: $fileName" -ForegroundColor Cyan
  
  try {
    switch ($fileExtension) {
      '.cab' {
        # Use DISM for .cab files
        Write-Host "  Using DISM for .cab installation..." -ForegroundColor Gray
        $dismArgs = @(
          '/Online'
          '/Add-Package'
          "/PackagePath:$FilePath"
          '/Quiet'
          '/NoRestart'
        )
        
        $process = Start-Process -FilePath 'DISM.exe' -ArgumentList $dismArgs -Wait -PassThru -NoNewWindow
        
        if ($process.ExitCode -eq 0) {
          Write-Host "  Installation successful: $fileName" -ForegroundColor Green
          return $true
        }
        elseif ($process.ExitCode -eq 3010) {
          Write-Host "  Installation successful (restart required): $fileName" -ForegroundColor Yellow
          return $true
        }
        else {
          Write-Host "  Installation failed: $fileName (Exit code: $($process.ExitCode))" -ForegroundColor Red
          return $false
        }
      }
      
      '.msu' {
        # Use WUSA for .msu files
        Write-Host "  Using WUSA for .msu installation..." -ForegroundColor Gray
        $wusaArgs = @(
          "$FilePath"
          '/quiet'
          '/norestart'
        )
        
        $process = Start-Process -FilePath 'wusa.exe' -ArgumentList $wusaArgs -Wait -PassThru -NoNewWindow
        
        if ($process.ExitCode -eq 0) {
          Write-Host "  Installation successful: $fileName" -ForegroundColor Green
          return $true
        }
        elseif ($process.ExitCode -eq 3010) {
          Write-Host "  Installation successful (restart required): $fileName" -ForegroundColor Yellow
          return $true
        }
        elseif ($process.ExitCode -eq -2145124329) {
          Write-Host "  Installation skipped: Update already installed - $fileName" -ForegroundColor Yellow
          return $true
        }
        else {
          Write-Host "  Installation failed: $fileName (Exit code: $($process.ExitCode))" -ForegroundColor Red
          return $false
        }
      }
      
      default {
        Write-Host "  Installation failed: Unsupported file type '$fileExtension' for $fileName" -ForegroundColor Red
        Write-Host "  Supported types: .cab (DISM), .msu (WUSA)" -ForegroundColor Gray
        return $false
      }
    }
  }
  catch {
    Write-Host "  Installation failed: $($_.Exception.Message)" -ForegroundColor Red
    return $false
  }
}

# Helper function to download updates with enhanced progress
function Invoke-UpdateDownload {
  param(
    [string]$Url,
    [string]$DestinationPath,
    [string]$KbId,
    [string]$Title,
    [int]$CurrentIndex = 1,
    [int]$TotalCount = 1
  )
  
  if ([string]::IsNullOrWhiteSpace($Url)) {
    return @{
      Success  = $false
      FilePath = $null
      FileSize = 0
      Reason   = "No download URL available"
    }
  }

  try {
    # Extract filename from URL or create one based on KB ID
    $fileName = Split-Path $Url -Leaf
    if ([string]::IsNullOrWhiteSpace($fileName) -or $fileName -notmatch '\.\w+$') {
      $fileName = "KB$KbId.msu"
    }
    
    $fullPath = Join-Path $DestinationPath $fileName
    
    # Progress header
    Write-Host "`n[$CurrentIndex/$TotalCount] Downloading KB$KbId" -ForegroundColor Cyan
    Write-Host "  Title: $Title" -ForegroundColor Gray
    Write-Host "  File: $fileName" -ForegroundColor Gray
    
    # Check if file already exists
    if (Test-Path $fullPath) {
      $existingSize = (Get-Item $fullPath).Length
      $existingSizeMB = [math]::Round($existingSize / 1MB, 2)
      Write-Host "  Status: File already exists ($existingSizeMB MB)" -ForegroundColor Yellow
      
      return @{
        Success  = $true
        FilePath = $fullPath
        FileSize = $existingSize
        Reason   = "File already existed"
      }
    }

    Write-Host "  URL: $Url" -ForegroundColor Gray
    Write-Host "  Downloading..." -ForegroundColor Yellow
    
    # Create a stopwatch for download timing
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    # Use System.Net.WebClient for better progress control
    $webClient = New-Object System.Net.WebClient
    $webClient.Headers.Add("User-Agent", "PowerShell Windows Update Downloader")
    
    # Add progress event handler
    $progressAction = {
      param($senderObj, $progressArgs)
      $percentComplete = [math]::Round(($progressArgs.BytesReceived / $progressArgs.TotalBytesToReceive) * 100, 1)
      $receivedMB = [math]::Round($progressArgs.BytesReceived / 1MB, 2)
      $totalMB = [math]::Round($progressArgs.TotalBytesToReceive / 1MB, 2)
      
      if ($progressArgs.TotalBytesToReceive -gt 0) {
        Write-Progress -Activity "Downloading $fileName" -Status "$receivedMB MB / $totalMB MB ($percentComplete%)" -PercentComplete $percentComplete
      }
    }
    
    # Register the event
    Register-ObjectEvent -InputObject $webClient -EventName DownloadProgressChanged -Action $progressAction | Out-Null
    
    try {
      # Start the download
      $webClient.DownloadFile($Url, $fullPath)
    }
    finally {
      # Clean up events and webclient
      Get-EventSubscriber | Where-Object { $_.SourceObject -eq $webClient } | Unregister-Event
      $webClient.Dispose()
      Write-Progress -Activity "Downloading $fileName" -Completed
    }
    
    $stopwatch.Stop()
    
    if (Test-Path $fullPath) {
      $fileSize = (Get-Item $fullPath).Length
      $fileSizeMB = [math]::Round($fileSize / 1MB, 2)
      $downloadSpeed = if ($stopwatch.Elapsed.TotalSeconds -gt 0) { 
        [math]::Round($fileSize / $stopwatch.Elapsed.TotalSeconds / 1MB, 2) 
      }
      else { 0 }
      
      Write-Host "  Status: Download completed successfully" -ForegroundColor Green
      Write-Host "  Size: $fileSizeMB MB" -ForegroundColor Green
      Write-Host "  Time: $($stopwatch.Elapsed.ToString('mm\:ss')) (${downloadSpeed} MB/s)" -ForegroundColor Green
      
      return @{
        Success  = $true
        FilePath = $fullPath
        FileSize = $fileSize
        Reason   = "Downloaded successfully"
      }
    }
    else {
      Write-Host "  Status: Download failed - File not found after download" -ForegroundColor Red
      return @{
        Success  = $false
        FilePath = $null
        FileSize = 0
        Reason   = "File not found after download"
      }
    }
  }
  catch {
    Write-Host "  Status: Download failed - $($_.Exception.Message)" -ForegroundColor Red
    return @{
      Success  = $false
      FilePath = $null
      FileSize = 0
      Reason   = $_.Exception.Message
    }
  }
}

# Helper function to install a batch of downloaded updates with progress visualization
function Invoke-UpdateBatchInstallation {
  param(
    [array]$UpdatesToInstall,
    [string]$InstallationMode = "Sequential" # Sequential or Parallel (future enhancement)
  )
  
  if (-not $UpdatesToInstall -or $UpdatesToInstall.Count -eq 0) {
    Write-Host "No updates to install." -ForegroundColor Yellow
    return
  }

  $totalUpdates = $UpdatesToInstall.Count
  $successfulInstalls = 0
  $failedInstalls = 0
  $installResults = @()

  Write-Host "`n" + "="*60 -ForegroundColor Magenta
  Write-Host "STARTING BATCH INSTALLATION" -ForegroundColor Magenta
  Write-Host "="*60 -ForegroundColor Magenta
  Write-Host "Mode: $InstallationMode" -ForegroundColor White
  Write-Host "Total updates to install: $totalUpdates" -ForegroundColor White
  Write-Host "="*60 -ForegroundColor Magenta

  for ($i = 0; $i -lt $totalUpdates; $i++) {
    $update = $UpdatesToInstall[$i]
    $currentIndex = $i + 1
    
    Write-Host "`n[$currentIndex/$totalUpdates] Installing KB$($update.KbId)" -ForegroundColor Magenta
    Write-Host "  Title: $($update.Title)" -ForegroundColor Gray
    Write-Host "  File: $(Split-Path $update.DownloadedFilePath -Leaf)" -ForegroundColor Gray
    
    # Create installation progress bar
    $percentComplete = [math]::Round(($currentIndex / $totalUpdates) * 100, 1)
    Write-Progress -Activity "Installing Windows Updates" -Status "Installing update $currentIndex of $totalUpdates (KB$($update.KbId))" -PercentComplete $percentComplete
    
    $installStart = Get-Date
    $installResult = Invoke-UpdateInstallation -FilePath $update.DownloadedFilePath -KbId $update.KbId -Title $update.Title
    $installEnd = Get-Date
    $installDuration = $installEnd - $installStart
    
    $resultObj = [PSCustomObject]@{
      KbId             = $update.KbId
      Title            = $update.Title
      FilePath         = $update.DownloadedFilePath
      Success          = $installResult
      Duration         = $installDuration
      InstallationTime = $installEnd
    }
    
    if ($installResult) {
      $successfulInstalls++
      Write-Host "  Status: Installation completed successfully" -ForegroundColor Green
      Write-Host "  Duration: $($installDuration.ToString('mm\:ss'))" -ForegroundColor Green
    }
    else {
      $failedInstalls++
      Write-Host "  Status: Installation failed" -ForegroundColor Red
      Write-Host "  Duration: $($installDuration.ToString('mm\:ss'))" -ForegroundColor Red
    }
    
    $installResults += $resultObj
    
    # Show progress summary
    Write-Host "  Progress: $successfulInstalls successful, $failedInstalls failed, $($totalUpdates - $currentIndex) remaining" -ForegroundColor Cyan
  }
  
  # Complete the progress bar
  Write-Progress -Activity "Installing Windows Updates" -Completed
  
  # Final installation summary
  Write-Host "`n" + "="*60 -ForegroundColor Magenta
  Write-Host "BATCH INSTALLATION COMPLETED" -ForegroundColor Magenta
  Write-Host "="*60 -ForegroundColor Magenta
  Write-Host "Total updates processed: $totalUpdates" -ForegroundColor White
  Write-Host "Successful installations: $successfulInstalls" -ForegroundColor Green
  Write-Host "Failed installations: $failedInstalls" -ForegroundColor Red
  Write-Host "Success rate: $([math]::Round(($successfulInstalls / $totalUpdates) * 100, 1))%" -ForegroundColor $(if ($successfulInstalls -eq $totalUpdates) { 'Green' } elseif ($successfulInstalls -gt $failedInstalls) { 'Yellow' } else { 'Red' })
  
  if ($failedInstalls -gt 0) {
    Write-Host "`nFailed installations:" -ForegroundColor Red
    $installResults | Where-Object { -not $_.Success } | ForEach-Object {
      Write-Host "  - KB$($_.KbId): $($_.Title)" -ForegroundColor Red
    }
  }
  
  if ($successfulInstalls -gt 0) {
    Write-Host "`nRecommendation: Restart the computer to complete the installation of $successfulInstalls update(s)" -ForegroundColor Yellow
  }
  
  Write-Host "="*60 -ForegroundColor Magenta
  
  return $installResults
}

# Helper function to download WSUS scan file
function Get-WSUSScanFile {
  param(
    [string]$DownloadPath,
    [string]$WSUSUrl = "https://catalog.s.download.windowsupdate.com/microsoftupdate/v6/wsusscan/wsusscn2.cab"
  )
  
  $cabFile = Join-Path $DownloadPath "wsusscn2.cab"
  
  try {
    Write-Host "Downloading WSUS scan file from Microsoft..." -ForegroundColor Cyan
    Write-Host "URL: $WSUSUrl" -ForegroundColor Gray
    Write-Host "Destination: $cabFile" -ForegroundColor Gray
    
    # Configure TLS/SSL settings for better compatibility
    $originalSecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol
    $originalServerCertificateValidationCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
    
    try {
      # Enable modern TLS versions
      [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13
      
      # Use Invoke-WebRequest for download with progress
      $progressPreference = $global:ProgressPreference
      $global:ProgressPreference = 'Continue'
      
      # Try download with enhanced parameters
      Invoke-WebRequest -Uri $WSUSUrl -OutFile $cabFile -UseBasicParsing -UserAgent "PowerShell WSUS Scanner" -TimeoutSec 300
      
      $global:ProgressPreference = $progressPreference
    }
    finally {
      # Restore original settings
      [System.Net.ServicePointManager]::SecurityProtocol = $originalSecurityProtocol
      [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $originalServerCertificateValidationCallback
    }
    
    if (Test-Path $cabFile) {
      $fileSize = (Get-Item $cabFile).Length
      $fileSizeMB = [math]::Round($fileSize / 1MB, 2)
      Write-Host "Downloaded successfully: wsusscn2.cab ($fileSizeMB MB)" -ForegroundColor Green
      return $cabFile
    }
    else {
      Write-Error "Download failed: File not found after download"
      return $null
    }
  }
  catch {
    Write-Host "Primary download method failed: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "Attempting alternative download method..." -ForegroundColor Yellow
    
    # Try alternative download method using System.Net.WebClient
    try {
      $webClient = New-Object System.Net.WebClient
      $webClient.Headers.Add("User-Agent", "PowerShell WSUS Scanner")
      $webClient.DownloadFile($WSUSUrl, $cabFile)
      $webClient.Dispose()
      
      if (Test-Path $cabFile) {
        $fileSize = (Get-Item $cabFile).Length
        $fileSizeMB = [math]::Round($fileSize / 1MB, 2)
        Write-Host "Downloaded successfully using alternative method: wsusscn2.cab ($fileSizeMB MB)" -ForegroundColor Green
        return $cabFile
      }
    }
    catch {
      Write-Host "Alternative download method also failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    Write-Error "All download methods failed. Please check your internet connection and try again, or manually download wsusscn2.cab from Microsoft and use the -WSUSScanFile parameter."
    return $null
  }
}

# Load the assembly needed for COM objects (once for the entire script)
[void][Reflection.Assembly]::LoadFrom("C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.VisualBasic.dll")

# Enum for Severity (defined once for the entire script)
# Check if the type already exists before defining it
if (-not ([System.Management.Automation.PSTypeName]'MsrcSeverity').Type) {
  Add-Type -TypeDefinition '
    public enum MsrcSeverity {
      Unspecified,
      Low,
      Moderate,
      Important,
      Critical
    }'
}

function Get-LocalUpdateStatus {
  #requires -Version 4
  [CmdletBinding(DefaultParameterSetName = 'ComputerName')]
  param (
    [Parameter(Position = 0, Mandatory = $true, ParameterSetName = 'ComputerName')]
    [Parameter(Position = 0, Mandatory = $true, ParameterSetName = 'WSUSOfflineScan')]
    [System.String]$ComputerName,

    [Parameter(Position = 1, Mandatory = $true, ParameterSetName = 'ComputerName')]
    [Parameter(Position = 4, Mandatory = $true, ParameterSetName = 'WSUSOfflineScan')]
    [ValidateNotNullOrEmpty()]
    [ValidateSet('IsHidden=0 and IsInstalled=0', 'IsHidden=0 and IsInstalled=1', 'IsInstalled=1', 'IsInstalled=0', 'IsHidden=0', 'IsHidden=1')]
    [System.String]$UpdateSearchFilter,

    [Parameter(Position = 2, Mandatory = $false)]
    [Switch]$DownloadUpdates,

    [Parameter(Position = 3, Mandatory = $false)]
    [Switch]$InstallUpdates,

    [Parameter(Position = 4, Mandatory = $false)]
    [ValidateScript({
        if ($_ -and -not (Test-Path $_ -PathType Container)) {
          throw "Download path '$_' does not exist or is not a directory."
        }
        return $true
      })]
    [System.String]$DownloadPath = "$env:TEMP\WindowsUpdates",

    [Parameter(Position = 5, Mandatory = $false)]
    [System.String]$ExportReport,

    [Parameter(Mandatory = $true, ParameterSetName = 'ImportReport')]
    [ValidateScript({
        if (-not (Test-Path $_ -PathType Leaf)) {
          throw "Import file '$_' does not exist."
        }
        return $true
      })]
    [System.String]$ImportReport,

    [Parameter(Mandatory = $true, ParameterSetName = 'WSUSOfflineScan')]
    [Switch]$WSUSOfflineScan,

    [Parameter(Position = 1, Mandatory = $false, ParameterSetName = 'WSUSOfflineScan')]
    [ValidateScript({
        if ($_ -and -not (Test-Path $_ -PathType Leaf)) {
          throw "WSUS scan file '$_' does not exist."
        }
        return $true
      })]
    [System.String]$WSUSScanFile,

    [Parameter(Position = 2, Mandatory = $false, ParameterSetName = 'WSUSOfflineScan')]
    [Switch]$DownloadWSUSScanFile,

    [Parameter(Position = 3, Mandatory = $false, ParameterSetName = 'WSUSOfflineScan')]
    [System.String]$WSUSScanFileDownloadPath = "$env:TEMP"
  )

  # Check for admin privileges
  if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script needs to be run As Admin" -ForegroundColor Red
    Write-Host "Furthermore, the user should be Admin on each computer/server from where you want to gather the Windows Update status!" -ForegroundColor Yellow
    break
  }

  # Validate parameter combinations
  if ($InstallUpdates -and -not $DownloadUpdates) {
    Write-Error "InstallUpdates requires DownloadUpdates to be enabled. Use both -DownloadUpdates and -InstallUpdates parameters."
    return
  }

  # Handle offline installation mode
  if ($PSCmdlet.ParameterSetName -eq 'OfflineInstall') {
    Write-Host "`nOffline Installation Mode: Installing updates from transferred files..." -ForegroundColor Cyan
    Write-Host "Scan report: $ScanReport" -ForegroundColor White
    Write-Host "Update files directory: $UpdateFilesPath" -ForegroundColor White
    
    try {
      # Load the original scan report
      $scanResults = Import-Clixml -Path $ScanReport
      
      if (-not $scanResults -or $scanResults.Count -eq 0) {
        Write-Error "No update data found in scan report file or file is invalid."
        return
      }
      
      Write-Host "Successfully loaded $($scanResults.Count) updates from scan report" -ForegroundColor Green
      
      # Get list of available update files in the directory
      $availableFiles = Get-ChildItem -Path $UpdateFilesPath -File -Include "*.msu", "*.cab" -Recurse
      Write-Host "Found $($availableFiles.Count) update files in directory" -ForegroundColor White
      
      # Match scan results with available files
      $MyUpdates = @()
      $matchedUpdates = @()
      
      foreach ($scanUpdate in $scanResults) {
        # Only process updates that were marked as missing in the original scan
        if ($scanUpdate.IsInstalled -eq $false) {
          $kbId = $scanUpdate.KbId
          
          # Look for matching files based on KB ID
          $matchingFiles = $availableFiles | Where-Object { 
            $_.Name -match "KB$kbId" -or $_.Name -match "$kbId"
          }
          
          if ($matchingFiles) {
            # Use the first matching file (in case there are multiple)
            $updateFile = $matchingFiles[0]
            
            # Create enhanced update object with file path
            $enhancedUpdate = $scanUpdate | Select-Object *
            $enhancedUpdate | Add-Member -MemberType NoteProperty -Name DownloadedFilePath -Value $updateFile.FullName -Force
            $enhancedUpdate | Add-Member -MemberType NoteProperty -Name DownloadedFileSize -Value $updateFile.Length -Force
            $enhancedUpdate | Add-Member -MemberType NoteProperty -Name DownloadSuccess -Value $true -Force
            $enhancedUpdate | Add-Member -MemberType NoteProperty -Name AvailableForInstall -Value $true -Force
            $enhancedUpdate | Add-Member -MemberType NoteProperty -Name MatchedFileName -Value $updateFile.Name -Force
            
            $matchedUpdates += $enhancedUpdate
            Write-Host "  ✓ Matched KB$kbId -> $($updateFile.Name)" -ForegroundColor Green
          }
          else {
            # Update not found in transferred files
            $enhancedUpdate = $scanUpdate | Select-Object *
            $enhancedUpdate | Add-Member -MemberType NoteProperty -Name DownloadSuccess -Value $false -Force
            $enhancedUpdate | Add-Member -MemberType NoteProperty -Name AvailableForInstall -Value $false -Force
            $enhancedUpdate | Add-Member -MemberType NoteProperty -Name MatchNote -Value "Update file not found in transferred files" -Force
            
            Write-Host "  ✗ No file found for KB$kbId" -ForegroundColor Yellow
          }
          
          $MyUpdates += $enhancedUpdate
        }
        else {
          # Update was already installed in original scan - add for completeness
          $enhancedUpdate = $scanUpdate | Select-Object *
          $enhancedUpdate | Add-Member -MemberType NoteProperty -Name AvailableForInstall -Value $false -Force
          $enhancedUpdate | Add-Member -MemberType NoteProperty -Name MatchNote -Value "Already installed in original scan" -Force
          $MyUpdates += $enhancedUpdate
        }
      }
      
      # Show matching summary
      Write-Host "`n" + "="*60 -ForegroundColor Blue
      Write-Host "FILE MATCHING SUMMARY" -ForegroundColor Blue
      Write-Host "="*60 -ForegroundColor Blue
      Write-Host "Updates from scan report: $($scanResults.Count)" -ForegroundColor White
      Write-Host "Updates that were missing: $(($scanResults | Where-Object { $_.IsInstalled -eq $false }).Count)" -ForegroundColor White
      Write-Host "Available update files: $($availableFiles.Count)" -ForegroundColor White
      Write-Host "Matched updates ready for install: $($matchedUpdates.Count)" -ForegroundColor Green
      Write-Host "="*60 -ForegroundColor Blue
      
      if ($matchedUpdates.Count -eq 0) {
        Write-Host "`nNo matching update files found for installation." -ForegroundColor Yellow
        Write-Host "Please ensure update files are properly named with KB numbers like KB5034441.msu" -ForegroundColor Yellow
        return $MyUpdates
      }
      
      # OFFLINE INSTALLATION PHASE
      Write-Host "`nProceeding with offline installation..." -ForegroundColor Cyan
      
      # Ask for confirmation before installing
      Write-Host "`nWARNING: About to install $($matchedUpdates.Count) Windows Update(s) from transferred files" -ForegroundColor Yellow
      Write-Host "This may require system restart(s) and could take significant time." -ForegroundColor Yellow
      
      # Show what will be installed
      Write-Host "`nUpdates to be installed:" -ForegroundColor White
      foreach ($update in $matchedUpdates) {
        Write-Host "  - KB$($update.KbId): $($update.Title)" -ForegroundColor Gray
        Write-Host "    File: $($update.MatchedFileName)" -ForegroundColor Gray
      }
      
      $confirmation = Read-Host "`nDo you want to proceed with installation? (Y/N)"
      
      if ($confirmation -eq 'Y' -or $confirmation -eq 'y' -or $confirmation -eq 'Yes') {
        $installResults = Invoke-UpdateBatchInstallation -UpdatesToInstall $matchedUpdates -InstallationMode "Sequential"
        
        # Update the original update objects with installation results
        foreach ($installResult in $installResults) {
          $originalUpdate = $MyUpdates | Where-Object { $_.KbId -eq $installResult.KbId }
          $originalUpdate | Add-Member -MemberType NoteProperty -Name InstallSuccess -Value $installResult.Success -Force
          $originalUpdate | Add-Member -MemberType NoteProperty -Name InstallDuration -Value $installResult.Duration -Force
          $originalUpdate | Add-Member -MemberType NoteProperty -Name InstallationTime -Value $installResult.InstallationTime -Force
        }
        
        # Final offline installation summary
        $successfulInstallations = ($MyUpdates | Where-Object { $_.InstallSuccess -eq $true }).Count
        $failedInstallations = ($MyUpdates | Where-Object { $_.InstallSuccess -eq $false -and $_.AvailableForInstall -eq $true }).Count
        
        Write-Host "`n" + "="*60 -ForegroundColor Cyan
        Write-Host "FINAL OFFLINE INSTALLATION SUMMARY" -ForegroundColor Cyan
        Write-Host "="*60 -ForegroundColor Cyan
        Write-Host "Updates from original scan: $($scanResults.Count)" -ForegroundColor White
        Write-Host "Updates available for install: $($matchedUpdates.Count)" -ForegroundColor White
        Write-Host "Successful installations: $successfulInstallations" -ForegroundColor Green
        Write-Host "Failed installations: $failedInstallations" -ForegroundColor Red
        Write-Host "Update files directory: $UpdateFilesPath" -ForegroundColor White
        
        if ($successfulInstallations -gt 0) {
          Write-Host "`nRecommendation: Restart the computer to complete the installation of $successfulInstallations update(s)" -ForegroundColor Yellow
        }
        
        Write-Host "="*60 -ForegroundColor Cyan
      }
      else {
        Write-Host "Installation cancelled by user." -ForegroundColor Yellow
        Write-Host "Update files remain available in: $UpdateFilesPath" -ForegroundColor Cyan
        
        # Mark all as not installed
        $matchedUpdates | ForEach-Object {
          $originalUpdate = $MyUpdates | Where-Object { $_.KbId -eq $_.KbId }
          $originalUpdate | Add-Member -MemberType NoteProperty -Name InstallSuccess -Value $false -Force
          $originalUpdate | Add-Member -MemberType NoteProperty -Name InstallNote -Value "Installation cancelled by user" -Force
        }
      }
      
      return $MyUpdates
    }
    catch {
      Write-Error "Failed to process offline installation: $($_.Exception.Message)"
      return
    }
  }
}

# Handle import report mode
if ($PSCmdlet.ParameterSetName -eq 'ImportReport') {
  Write-Host "`nImport Report Mode: Loading update data from file..." -ForegroundColor Cyan
  Write-Host "Import file: $ImportReport" -ForegroundColor White
    
  try {
    $importedData = Import-Clixml -Path $ImportReport
      
    if (-not $importedData -or $importedData.Count -eq 0) {
      Write-Error "No update data found in import file or file is invalid."
      return
    }
      
    Write-Host "Successfully loaded $($importedData.Count) updates from report" -ForegroundColor Green
      
    # If download is requested, process downloads for imported data
    if ($DownloadUpdates) {
      Write-Host "`nDownload mode enabled for imported updates..." -ForegroundColor Yellow
        
      # Create download directory
      if (-not (Test-Path $DownloadPath)) {
        try {
          New-Item -Path $DownloadPath -ItemType Directory -Force | Out-Null
          Write-Host "Created download directory: $DownloadPath" -ForegroundColor Green
        }
        catch {
          Write-Error "Failed to create download directory: $DownloadPath. Error: $($_.Exception.Message)"
          return
        }
      }
        
      # Prepare imported updates for batch processing
      $MyUpdates = @()
      foreach ($update in $importedData) {
        if ($update.DownloadURL) {
          $update | Add-Member -MemberType NoteProperty -Name NeedsDownload -Value $true -Force
        }
        else {
          $update | Add-Member -MemberType NoteProperty -Name DownloadSuccess -Value $false -Force
          $update | Add-Member -MemberType NoteProperty -Name DownloadNote -Value "No direct URL - manual download required" -Force
          $update | Add-Member -MemberType NoteProperty -Name NeedsDownload -Value $false -Force
          if ($InstallUpdates) {
            $update | Add-Member -MemberType NoteProperty -Name InstallSuccess -Value $false -Force
          }
        }
        $MyUpdates += $update
      }
        
      # PHASE 1: BATCH DOWNLOAD PROCESSING (IMPORT MODE)
      $updatesToDownload = $MyUpdates | Where-Object { $_.NeedsDownload -eq $true }
        
      if ($updatesToDownload -and $updatesToDownload.Count -gt 0) {
        Write-Host "`n" + "="*60 -ForegroundColor Green
        Write-Host "STARTING BATCH DOWNLOAD PHASE (IMPORT MODE)" -ForegroundColor Green
        Write-Host "="*60 -ForegroundColor Green
        Write-Host "Updates to download: $($updatesToDownload.Count)" -ForegroundColor White
        Write-Host "Download directory: $DownloadPath" -ForegroundColor White
        Write-Host "="*60 -ForegroundColor Green
          
        # Process downloads with progress visualization
        for ($i = 0; $i -lt $updatesToDownload.Count; $i++) {
          $update = $updatesToDownload[$i]
          $currentIndex = $i + 1
            
          $downloadResult = Invoke-UpdateDownload -Url $update.DownloadURL -DestinationPath $DownloadPath -KbId $update.KbId -Title $update.Title -CurrentIndex $currentIndex -TotalCount $updatesToDownload.Count
            
          # Update the original update object with download results
          $originalUpdate = $MyUpdates | Where-Object { $_.KbId -eq $update.KbId }
          $originalUpdate | Add-Member -MemberType NoteProperty -Name DownloadSuccess -Value $downloadResult.Success -Force
          $originalUpdate | Add-Member -MemberType NoteProperty -Name DownloadedFilePath -Value $downloadResult.FilePath -Force
          $originalUpdate | Add-Member -MemberType NoteProperty -Name DownloadedFileSize -Value $downloadResult.FileSize -Force
          $originalUpdate | Add-Member -MemberType NoteProperty -Name DownloadReason -Value $downloadResult.Reason -Force
        }
          
        # Download phase summary
        $successfulDownloads = ($MyUpdates | Where-Object { $_.DownloadSuccess -eq $true }).Count
        $failedDownloads = ($MyUpdates | Where-Object { $_.DownloadSuccess -eq $false -and $_.NeedsDownload -eq $true }).Count
        $totalDownloadSize = ($MyUpdates | Where-Object { $_.DownloadSuccess -eq $true } | Measure-Object -Property DownloadedFileSize -Sum).Sum
        $totalDownloadSizeMB = [math]::Round($totalDownloadSize / 1MB, 2)
          
        Write-Host "`n" + "="*60 -ForegroundColor Green
        Write-Host "DOWNLOAD PHASE COMPLETED (IMPORT MODE)" -ForegroundColor Green
        Write-Host "="*60 -ForegroundColor Green
        Write-Host "Successful downloads: $successfulDownloads" -ForegroundColor Green
        Write-Host "Failed downloads: $failedDownloads" -ForegroundColor Red
        Write-Host "Total downloaded: $totalDownloadSizeMB MB" -ForegroundColor Green
        Write-Host "Download directory: $DownloadPath" -ForegroundColor White
        Write-Host "="*60 -ForegroundColor Green
      }
      else {
        Write-Host "`nNo updates available for download (all updates either have no URL or already downloaded)" -ForegroundColor Yellow
      }

      # PHASE 2: BATCH INSTALLATION PROCESSING (IMPORT MODE)
      if ($InstallUpdates) {
        $updatesToInstall = $MyUpdates | Where-Object { $_.DownloadSuccess -eq $true -and $_.DownloadedFilePath }
          
        if ($updatesToInstall -and $updatesToInstall.Count -gt 0) {
          Write-Host "`nProceeding with batch installation..." -ForegroundColor Cyan
            
          # Ask for confirmation before installing
          Write-Host "`nWARNING: About to install $($updatesToInstall.Count) Windows Update(s)" -ForegroundColor Yellow
          Write-Host "This may require system restart(s) and could take significant time." -ForegroundColor Yellow
          $confirmation = Read-Host "Do you want to proceed with installation? (Y/N)"
            
          if ($confirmation -eq 'Y' -or $confirmation -eq 'y' -or $confirmation -eq 'Yes') {
            $installResults = Invoke-UpdateBatchInstallation -UpdatesToInstall $updatesToInstall -InstallationMode "Sequential"
              
            # Update the original update objects with installation results
            foreach ($installResult in $installResults) {
              $originalUpdate = $MyUpdates | Where-Object { $_.KbId -eq $installResult.KbId }
              $originalUpdate | Add-Member -MemberType NoteProperty -Name InstallSuccess -Value $installResult.Success -Force
              $originalUpdate | Add-Member -MemberType NoteProperty -Name InstallDuration -Value $installResult.Duration -Force
              $originalUpdate | Add-Member -MemberType NoteProperty -Name InstallationTime -Value $installResult.InstallationTime -Force
            }
          }
          else {
            Write-Host "Installation cancelled by user." -ForegroundColor Yellow
            Write-Host "Updates have been downloaded to: $DownloadPath" -ForegroundColor Cyan
            Write-Host "You can install them manually later or run the script again with -InstallUpdates" -ForegroundColor Cyan
              
            # Mark all as not installed
            $updatesToInstall | ForEach-Object {
              $originalUpdate = $MyUpdates | Where-Object { $_.KbId -eq $_.KbId }
              $originalUpdate | Add-Member -MemberType NoteProperty -Name InstallSuccess -Value $false -Force
              $originalUpdate | Add-Member -MemberType NoteProperty -Name InstallNote -Value "Installation cancelled by user" -Force
            }
          }
        }
        else {
          Write-Host "`nNo updates available for installation (no successfully downloaded updates found)" -ForegroundColor Yellow
        }
      }

      # Handle updates without direct download URLs (IMPORT MODE)
      $updatesWithoutUrls = $MyUpdates | Where-Object { $_.NeedsDownload -eq $false -and $null -eq $_.DownloadURL }
      if ($updatesWithoutUrls -and $updatesWithoutUrls.Count -gt 0) {
        Write-Host "`n" + "="*60 -ForegroundColor Yellow
        Write-Host "MANUAL DOWNLOAD REQUIRED (IMPORT MODE)" -ForegroundColor Yellow
        Write-Host "="*60 -ForegroundColor Yellow
        Write-Host "The following $($updatesWithoutUrls.Count) update(s) require manual download:" -ForegroundColor Yellow
          
        foreach ($update in $updatesWithoutUrls) {
          Write-Host "`nKB$($update.KbId): $($update.Title)" -ForegroundColor White
          if ($update.MicrosoftCatalogURL) {
            Write-Host "  Download URL: $($update.MicrosoftCatalogURL)" -ForegroundColor Cyan
          }
          Write-Host "  Alternative: Use Windows Update, WSUS, or manually search Microsoft Update Catalog" -ForegroundColor Gray
        }
          
        Write-Host "`nTip: Visit Microsoft Update Catalog (catalog.update.microsoft.com) for manual downloads" -ForegroundColor Green
        Write-Host "="*60 -ForegroundColor Yellow
      }
        
      # Display final summary for import mode
      $totalUpdates = $MyUpdates.Count
      $updatesWithUrls = ($MyUpdates | Where-Object { $_.DownloadURL }).Count
      $successfulDownloads = ($MyUpdates | Where-Object { $_.DownloadSuccess -eq $true }).Count
        
      $summaryTitle = if ($InstallUpdates) { "FINAL IMPORT, DOWNLOAD `& INSTALLATION SUMMARY" } else { "FINAL IMPORT `& DOWNLOAD SUMMARY" }
      Write-Host "`n" + "="*60 -ForegroundColor Cyan
      Write-Host $summaryTitle -ForegroundColor Cyan
      Write-Host "="*60 -ForegroundColor Cyan
      Write-Host "Total updates imported: $totalUpdates" -ForegroundColor White
      Write-Host "Updates with download URLs: $updatesWithUrls" -ForegroundColor White
      Write-Host "Successful downloads: $successfulDownloads" -ForegroundColor Green
        
      if ($InstallUpdates) {
        $successfulInstallations = ($MyUpdates | Where-Object { $_.InstallSuccess -eq $true }).Count
        $failedInstallations = ($MyUpdates | Where-Object { $_.InstallSuccess -eq $false -and $_.DownloadSuccess -eq $true }).Count
        Write-Host "Successful installations: $successfulInstallations" -ForegroundColor Green
        if ($failedInstallations -gt 0) {
          Write-Host "Failed installations: $failedInstallations" -ForegroundColor Red
        }
      }
        
      Write-Host "Download location: $DownloadPath" -ForegroundColor White
      Write-Host "="*60 -ForegroundColor Cyan
        
      return $MyUpdates
    }
    else {
      # Just return the imported data without downloading
      return $importedData
    }
  }
  catch {
    Write-Error "Failed to import report file: $($_.Exception.Message)"
    return
  }
}

# Handle WSUS offline scan mode
if ($PSCmdlet.ParameterSetName -eq 'WSUSOfflineScan') {
  Write-Host "`nWSUS Offline Scan Mode: Scanning with wsusscn2.cab..." -ForegroundColor Cyan
    
  $scanFile = $WSUSScanFile
    
  # Download wsusscn2.cab if requested or no file provided
  if ($DownloadWSUSScanFile -or -not $WSUSScanFile) {
    if (-not (Test-Path $WSUSScanFileDownloadPath)) {
      try {
        New-Item -Path $WSUSScanFileDownloadPath -ItemType Directory -Force | Out-Null
      }
      catch {
        Write-Error "Failed to create download directory: $WSUSScanFileDownloadPath. Error: $($_.Exception.Message)"
        return
      }
    }
      
    $scanFile = Get-WSUSScanFile -DownloadPath $WSUSScanFileDownloadPath
    if (-not $scanFile) {
      Write-Error "Failed to obtain WSUS scan file. Cannot proceed with offline scan."
      return
    }
  }
    
  if (-not (Test-Path $scanFile)) {
    Write-Error "WSUS scan file not found: $scanFile"
    return
  }
    
  # Resolve to absolute path to ensure COM objects can find the file
  $scanFile = Resolve-Path $scanFile | Select-Object -ExpandProperty Path
  Write-Host "Using WSUS scan file: $scanFile" -ForegroundColor White
    
  try {
    # Create update session and searcher for offline scan
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
      
    # Create the service manager for offline scanning
    $updateServiceManager = New-Object -ComObject Microsoft.Update.ServiceManager
      
    Write-Host "Setting up offline scan service..." -ForegroundColor Gray
      
    # Add the scan package service using the wsusscn2.cab file
    # This is the correct way - only 2 parameters, not 3
    try {
      $updateService = $updateServiceManager.AddScanPackageService("Offline Sync Service", $scanFile)
      Write-Host "Service ID: $($updateService.ServiceID)" -ForegroundColor Gray
        
      # Configure the searcher to use our offline service
      $searcher.ServerSelection = 3  # ssOthers (use specified service)
      $searcher.ServiceID = $updateService.ServiceID
        
      Write-Host "Offline scan service configured successfully" -ForegroundColor Green
    }
    catch {
      $exceptionObject = $_
      $hresult = '{0:x}' -f $exceptionObject.Exception.GetBaseException().HResult
        
      switch ($hresult) {
        # E_ACCESSDENIED
        '80070005' {
          Write-Error "AddScanPackageService received an AccessDenied exception. Run PowerShell as Administrator."
          return
        }
        # E_INVALIDARG  
        '80070057' {
          Write-Error "AddScanPackageService received invalid arguments. Check that the wsusscn2.cab file is valid."
          return
        }
        # File not found
        '80070002' {
          Write-Error "wsusscn2.cab file could not be found: $scanFile"
          return
        }
        default {
          Write-Error "Error setting up offline scan service: $($_.Exception.Message)"
          Write-Host "HRESULT: 0x$hresult" -ForegroundColor Red
          return
        }
      }
    }
      
    # Perform offline scan with specified filter criteria
    Write-Host "Performing offline scan with filter: $UpdateSearchFilter..." -ForegroundColor Yellow
    try {
      $results = $searcher.Search($UpdateSearchFilter)
      Write-Host "Found $($results.Updates.Count) updates via offline scan" -ForegroundColor Green
        
      # If we found 0 updates, let's try a broader search to verify the scan is working
      if ($results.Updates.Count -eq 0) {
        Write-Host "No updates found with current filter. Testing with broader search..." -ForegroundColor Yellow
        $testResults = $searcher.Search("1=1")  # Search for all updates
        Write-Host "Total updates in scan file: $($testResults.Updates.Count)" -ForegroundColor Cyan
          
        if ($testResults.Updates.Count -eq 0) {
          Write-Warning "The wsusscn2.cab file appears to be empty or invalid. Try downloading a fresh copy."
        }
        else {
          Write-Host "The scan file contains updates, but none match your filter criteria." -ForegroundColor Yellow
          Write-Host "Try different filters like 'IsInstalled=0' or 'IsHidden=0'" -ForegroundColor Yellow
        }
      }
    }
    catch {
      $exceptionObject = $_
      $hresult = '{0:x}' -f $exceptionObject.Exception.GetBaseException().HResult
        
      switch ($hresult) {
        # WU_E_LEGACYSERVER
        '80244003' {
          Write-Error "Target is Microsoft Software Update Services (SUS) 1.0 server."
          return
        }
        # E_POINTER
        '8024002B' {
          Write-Error "Search received invalid argument: $UpdateSearchFilter"
          return
        }
        # WU_E_INVALID_CRITERIA
        '80240032' {
          Write-Error "Invalid search filter: $UpdateSearchFilter"
          return
        }
        default {
          Write-Error "Error during offline scan: $($_.Exception.Message)"
          Write-Host "HRESULT: 0x$hresult" -ForegroundColor Red
          return
        }
      }
    }
      
    # Clean up the temporary service
    Write-Host "Cleaning up offline scan service..." -ForegroundColor Gray
    try {
      $updateServiceManager.RemoveService($updateService.ServiceID)
    }
    catch {
      Write-Warning "Could not remove temporary service: $($_.Exception.Message)"
    }
      
    # Process results similar to normal scan
    $MyUpdates = @()
      
    foreach ($update in $results.Updates) {
      $downloadUrl = $update.BundledUpdates | ForEach-Object {
        $_.DownloadContents | ForEach-Object {
          $_.DownloadUrl
        }
      } | Select-Object -First 1

      $severity = 0
      try {
        $severity = ([int][MsrcSeverity]$update.MsrcSeverity)
      }
      catch {}

      $bulletinId = ($update.SecurityBulletinIDs | Select-Object -First 1)
      $bulletinUrl = if ($bulletinId) {
        'http://www.microsoft.com/technet/security/bulletin/{0}.mspx' -f $bulletinId
      }
      else {
        [System.String]::Empty
      }

      # Create manual download guidance for updates without direct download URLs
      $manualDownloadInfo = ""
      $microsoftCatalogUrl = ""
        
      if (-not $downloadUrl -and $update.KBArticleIDs.Count -gt 0) {
        $kbId = $update.KBArticleIDs | Select-Object -First 1
        $microsoftCatalogUrl = "https://www.catalog.update.microsoft.com/Search.aspx?q=KB$kbId"
        $manualDownloadInfo = "No direct download URL available. Manual download: Microsoft Update Catalog"
      }

      $updates = New-Object -TypeName psobject |
      Add-Member -MemberType NoteProperty -Name Computer -Value "$env:computername" -PassThru -Force |
      Add-Member -MemberType NoteProperty -Name Id -Value ($update.SecurityBulletinIDs | Select-Object -First 1) -PassThru -Force |
      Add-Member -MemberType NoteProperty -Name CVEIds -Value ($update.cveids | Select-Object -First 1) -PassThru -Force |
      Add-Member -MemberType NoteProperty -Name BulletinId -Value $bulletinId -PassThru -Force |
      Add-Member -MemberType NoteProperty -Name KbId -Value ($update.KBArticleIDs | Select-Object -First 1) -PassThru -Force |
      Add-Member -MemberType NoteProperty -Name Type -Value $update.Type -PassThru -Force |
      Add-Member -MemberType NoteProperty -Name IsInstalled -Value $update.IsInstalled -PassThru -Force |
      Add-Member -MemberType NoteProperty -Name InstalledOn -Value $update.LastDeploymentChangeTime -PassThru -Force |
      Add-Member -MemberType NoteProperty -Name RestartRequired -Value $update.RebootRequired -PassThru -Force |
      Add-Member -MemberType NoteProperty -Name Title -Value $update.Title -PassThru -Force |
      Add-Member -MemberType NoteProperty -Name Description -Value $update.Description -PassThru -Force |
      Add-Member -MemberType NoteProperty -Name SeverityText -Value ([MsrcSeverity][int]$severity) -PassThru -Force |
      Add-Member -MemberType NoteProperty -Name Severity -Value $severity -PassThru -ErrorAction SilentlyContinue -Force |
      Add-Member -MemberType NoteProperty -Name InformationURL -Value ($update.MoreInfoUrls | Select-Object -First 1) -PassThru -Force |
      Add-Member -MemberType NoteProperty -Name SupportURL -Value $update.supporturl -PassThru -Force |
      Add-Member -MemberType NoteProperty -Name DownloadURL -Value $downloadUrl -PassThru -Force |
      Add-Member -MemberType NoteProperty -Name ManualDownloadInfo -Value $manualDownloadInfo -PassThru -Force |
      Add-Member -MemberType NoteProperty -Name MicrosoftCatalogURL -Value $microsoftCatalogUrl -PassThru -Force |
      Add-Member -MemberType NoteProperty -Name BulletinURL -Value $bulletinUrl -PassThru -Force |
      Add-Member -MemberType NoteProperty -Name ScanMethod -Value "WSUS Offline" -PassThru -Force

      # Download update if DownloadUpdates switch is enabled and URL is available
      if ($DownloadUpdates -and $downloadUrl) {
        # Store download info for batch processing later
        $updates | Add-Member -MemberType NoteProperty -Name DownloadURL -Value $downloadUrl -Force
        $updates | Add-Member -MemberType NoteProperty -Name KbId -Value $kbId -Force
        $updates | Add-Member -MemberType NoteProperty -Name NeedsDownload -Value $true -Force
      }
      elseif ($DownloadUpdates -and -not $downloadUrl) {
        $updates | Add-Member -MemberType NoteProperty -Name DownloadSuccess -Value $false -Force
        $updates | Add-Member -MemberType NoteProperty -Name DownloadNote -Value "No direct URL - manual download required" -Force
        $updates | Add-Member -MemberType NoteProperty -Name NeedsDownload -Value $false -Force
        if ($InstallUpdates) {
          $updates | Add-Member -MemberType NoteProperty -Name InstallSuccess -Value $false -Force
        }
      }

      $MyUpdates += $updates
    }
      
    # PHASE 1: BATCH DOWNLOAD PROCESSING (WSUS Offline Scan)
    if ($DownloadUpdates) {
      if (-not (Test-Path $DownloadPath)) {
        try {
          New-Item -Path $DownloadPath -ItemType Directory -Force | Out-Null
          Write-Host "Created download directory: $DownloadPath" -ForegroundColor Green
        }
        catch {
          Write-Error "Failed to create download directory: $DownloadPath. Error: $($_.Exception.Message)"
          return
        }
      }
        
      $updatesToDownload = $MyUpdates | Where-Object { $_.NeedsDownload -eq $true }
        
      if ($updatesToDownload -and $updatesToDownload.Count -gt 0) {
        Write-Host "`n" + "="*60 -ForegroundColor Green
        Write-Host "STARTING BATCH DOWNLOAD PHASE (WSUS OFFLINE)" -ForegroundColor Green
        Write-Host "="*60 -ForegroundColor Green
        Write-Host "Updates to download: $($updatesToDownload.Count)" -ForegroundColor White
        Write-Host "Download directory: $DownloadPath" -ForegroundColor White
        Write-Host "="*60 -ForegroundColor Green
          
        # Process downloads with progress visualization
        for ($i = 0; $i -lt $updatesToDownload.Count; $i++) {
          $update = $updatesToDownload[$i]
          $currentIndex = $i + 1
            
          $downloadResult = Invoke-UpdateDownload -Url $update.DownloadURL -DestinationPath $DownloadPath -KbId $update.KbId -Title $update.Title -CurrentIndex $currentIndex -TotalCount $updatesToDownload.Count
            
          # Update the original update object with download results
          $originalUpdate = $MyUpdates | Where-Object { $_.KbId -eq $update.KbId }
          $originalUpdate | Add-Member -MemberType NoteProperty -Name DownloadSuccess -Value $downloadResult.Success -Force
          $originalUpdate | Add-Member -MemberType NoteProperty -Name DownloadedFilePath -Value $downloadResult.FilePath -Force
          $originalUpdate | Add-Member -MemberType NoteProperty -Name DownloadedFileSize -Value $downloadResult.FileSize -Force
          $originalUpdate | Add-Member -MemberType NoteProperty -Name DownloadReason -Value $downloadResult.Reason -Force
        }
          
        # Download phase summary
        $successfulDownloads = ($MyUpdates | Where-Object { $_.DownloadSuccess -eq $true }).Count
        $failedDownloads = ($MyUpdates | Where-Object { $_.DownloadSuccess -eq $false -and $_.NeedsDownload -eq $true }).Count
        $totalDownloadSize = ($MyUpdates | Where-Object { $_.DownloadSuccess -eq $true } | Measure-Object -Property DownloadedFileSize -Sum).Sum
        $totalDownloadSizeMB = [math]::Round($totalDownloadSize / 1MB, 2)
          
        Write-Host "`n" + "="*60 -ForegroundColor Green
        Write-Host "DOWNLOAD PHASE COMPLETED (WSUS OFFLINE)" -ForegroundColor Green
        Write-Host "="*60 -ForegroundColor Green
        Write-Host "Successful downloads: $successfulDownloads" -ForegroundColor Green
        Write-Host "Failed downloads: $failedDownloads" -ForegroundColor Red
        Write-Host "Total downloaded: $totalDownloadSizeMB MB" -ForegroundColor Green
        Write-Host "Download directory: $DownloadPath" -ForegroundColor White
        Write-Host "="*60 -ForegroundColor Green
      }
      else {
        Write-Host "`nNo updates available for download (all updates either have no URL or already downloaded)" -ForegroundColor Yellow
      }
    }

    # PHASE 2: BATCH INSTALLATION PROCESSING (WSUS Offline Scan)
    if ($InstallUpdates) {
      $updatesToInstall = $MyUpdates | Where-Object { $_.DownloadSuccess -eq $true -and $_.DownloadedFilePath }
        
      if ($updatesToInstall -and $updatesToInstall.Count -gt 0) {
        Write-Host "`nProceeding with batch installation..." -ForegroundColor Cyan
          
        # Ask for confirmation before installing
        Write-Host "`nWARNING: About to install $($updatesToInstall.Count) Windows Update(s)" -ForegroundColor Yellow
        Write-Host "This may require system restart(s) and could take significant time." -ForegroundColor Yellow
        $confirmation = Read-Host "Do you want to proceed with installation? (Y/N)"
          
        if ($confirmation -eq 'Y' -or $confirmation -eq 'y' -or $confirmation -eq 'Yes') {
          $installResults = Invoke-UpdateBatchInstallation -UpdatesToInstall $updatesToInstall -InstallationMode "Sequential"
            
          # Update the original update objects with installation results
          foreach ($installResult in $installResults) {
            $originalUpdate = $MyUpdates | Where-Object { $_.KbId -eq $installResult.KbId }
            $originalUpdate | Add-Member -MemberType NoteProperty -Name InstallSuccess -Value $installResult.Success -Force
            $originalUpdate | Add-Member -MemberType NoteProperty -Name InstallDuration -Value $installResult.Duration -Force
            $originalUpdate | Add-Member -MemberType NoteProperty -Name InstallationTime -Value $installResult.InstallationTime -Force
          }
        }
        else {
          Write-Host "Installation cancelled by user." -ForegroundColor Yellow
          Write-Host "Updates have been downloaded to: $DownloadPath" -ForegroundColor Cyan
          Write-Host "You can install them manually later or run the script again with -InstallUpdates" -ForegroundColor Cyan
            
          # Mark all as not installed
          $updatesToInstall | ForEach-Object {
            $originalUpdate = $MyUpdates | Where-Object { $_.KbId -eq $_.KbId }
            $originalUpdate | Add-Member -MemberType NoteProperty -Name InstallSuccess -Value $false -Force
            $originalUpdate | Add-Member -MemberType NoteProperty -Name InstallNote -Value "Installation cancelled by user" -Force
          }
        }
      }
      else {
        Write-Host "`nNo updates available for installation (no successfully downloaded updates found)" -ForegroundColor Yellow
      }
    }

    # Handle updates without direct download URLs (WSUS Offline)
    $updatesWithoutUrls = $MyUpdates | Where-Object { $_.NeedsDownload -eq $false -and $null -eq $_.DownloadURL }
    if ($DownloadUpdates -and $updatesWithoutUrls -and $updatesWithoutUrls.Count -gt 0) {
      Write-Host "`n" + "="*60 -ForegroundColor Yellow
      Write-Host "MANUAL DOWNLOAD REQUIRED (WSUS OFFLINE)" -ForegroundColor Yellow
      Write-Host "="*60 -ForegroundColor Yellow
      Write-Host "The following $($updatesWithoutUrls.Count) update(s) require manual download:" -ForegroundColor Yellow
        
      foreach ($update in $updatesWithoutUrls) {
        Write-Host "`nKB$($update.KbId): $($update.Title)" -ForegroundColor White
        if ($update.MicrosoftCatalogURL) {
          Write-Host "  Download URL: $($update.MicrosoftCatalogURL)" -ForegroundColor Cyan
        }
        Write-Host "  Alternative: Use Windows Update, WSUS, or manually search Microsoft Update Catalog" -ForegroundColor Gray
      }
        
      Write-Host "`nTip: Visit Microsoft Update Catalog (catalog.update.microsoft.com) for manual downloads" -ForegroundColor Green
      Write-Host "="*60 -ForegroundColor Yellow
    }
      
    # Export report if requested
    if ($ExportReport) {
      try {
        $exportPath = $ExportReport
        if (-not $exportPath.EndsWith('.xml')) {
          $exportPath += '.xml'
        }
          
        # Create directory if it doesn't exist
        $exportDir = Split-Path $exportPath -Parent
        if ($exportDir -and -not (Test-Path $exportDir)) {
          New-Item -Path $exportDir -ItemType Directory -Force | Out-Null
          Write-Host "Created export directory: $exportDir" -ForegroundColor Green
        }
          
        Export-Clixml -InputObject $MyUpdates -Path $exportPath -Force
        Write-Host "`nWSUS Offline scan report exported successfully to: $exportPath" -ForegroundColor Green
      }
      catch {
        Write-Error "Failed to export report: $($_.Exception.Message)"
      }
    }
      
    # Display final summary for WSUS offline scan
    $totalUpdates = $MyUpdates.Count
    $criticalUpdates = ($MyUpdates | Where-Object { $_.SeverityText -eq 'Critical' }).Count
    $importantUpdates = ($MyUpdates | Where-Object { $_.SeverityText -eq 'Important' }).Count
      
    $summaryTitle = if ($InstallUpdates) { "FINAL WSUS OFFLINE SCAN, DOWNLOAD `& INSTALLATION SUMMARY" } else { "FINAL WSUS OFFLINE SCAN SUMMARY" }
    Write-Host "`n" + "="*60 -ForegroundColor Cyan
    Write-Host $summaryTitle -ForegroundColor Cyan
    Write-Host "="*60 -ForegroundColor Cyan
    Write-Host "Scan file used: $(Split-Path $scanFile -Leaf)" -ForegroundColor White
    Write-Host "Search filter: $UpdateSearchFilter" -ForegroundColor White
    Write-Host "Total updates found: $totalUpdates" -ForegroundColor White
    Write-Host "Critical updates: $criticalUpdates" -ForegroundColor Red
    Write-Host "Important updates: $importantUpdates" -ForegroundColor Yellow
      
    if ($DownloadUpdates) {
      $updatesWithUrls = ($MyUpdates | Where-Object { $_.DownloadURL }).Count
      $updatesWithoutUrls = $totalUpdates - $updatesWithUrls
      $successfulDownloads = ($MyUpdates | Where-Object { $_.DownloadSuccess -eq $true }).Count
      Write-Host "Updates with download URLs: $updatesWithUrls" -ForegroundColor White
      Write-Host "Updates requiring manual download: $updatesWithoutUrls" -ForegroundColor Yellow
      Write-Host "Successful downloads: $successfulDownloads" -ForegroundColor Green
        
      if ($InstallUpdates) {
        $successfulInstallations = ($MyUpdates | Where-Object { $_.InstallSuccess -eq $true }).Count
        $failedInstallations = ($MyUpdates | Where-Object { $_.InstallSuccess -eq $false -and $_.DownloadSuccess -eq $true }).Count
        Write-Host "Successful installations: $successfulInstallations" -ForegroundColor Green
        if ($failedInstallations -gt 0) {
          Write-Host "Failed installations: $failedInstallations" -ForegroundColor Red
        }
      }
        
      Write-Host "Download location: $DownloadPath" -ForegroundColor White
    }
      
    Write-Host "="*60 -ForegroundColor Cyan
      
    return $MyUpdates
  }
  catch {
    Write-Error "WSUS offline scan failed: $($_.Exception.Message)"
    Write-Host "`nDetailed error information:" -ForegroundColor Red
    Write-Host "  Error Type: $($_.Exception.GetType().Name)" -ForegroundColor Red
    Write-Host "  Scan File: $scanFile" -ForegroundColor Red
    Write-Host "  File Exists: $(Test-Path $scanFile)" -ForegroundColor Red
    if (Test-Path $scanFile) {
      $fileInfo = Get-Item $scanFile
      Write-Host "  File Size: $([math]::Round($fileInfo.Length / 1MB, 2)) MB" -ForegroundColor Red
    }
    Write-Host "`nTroubleshooting suggestions:" -ForegroundColor Yellow
    Write-Host "  1. Ensure you're running PowerShell as Administrator" -ForegroundColor Yellow
    Write-Host "  2. Verify wsusscn2.cab is a valid Microsoft file (100-200MB)" -ForegroundColor Yellow
    Write-Host "  3. Try downloading a fresh wsusscn2.cab from Microsoft" -ForegroundColor Yellow
    Write-Host "  4. Use absolute path instead of relative path" -ForegroundColor Yellow
    return
  }
}

# Display Windows Update source
$wuRegPath = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"
if (Test-Path $wuRegPath) {
  $wuSettings = Get-ItemProperty -Path $wuRegPath
  $wuServer = $wuSettings.WUServer
  $wuStatusServer = $wuSettings.WUStatusServer

  if ($wuServer) {
    Write-Host "`nWindows Update is configured to use WSUS:" -ForegroundColor Cyan
    Write-Host "WUServer      : $wuServer"
    Write-Host "WUStatusServer: $wuStatusServer`n"
  }
  else {
    Write-Host "`nWindows Update is using Microsoft Update (default)" -ForegroundColor Cyan
  }
}
else {
  Write-Host "`nWindows Update is using Microsoft Update (default)" -ForegroundColor Cyan
}

# Create download directory if DownloadUpdates is specified
if ($DownloadUpdates) {
  if (-not (Test-Path $DownloadPath)) {
    try {
      New-Item -Path $DownloadPath -ItemType Directory -Force | Out-Null
      Write-Host "`nCreated download directory: $DownloadPath" -ForegroundColor Green
    }
    catch {
      Write-Error "Failed to create download directory: $DownloadPath. Error: $($_.Exception.Message)"
      return
    }
  }
  Write-Host "`nDownload mode enabled. Files will be saved to: $DownloadPath" -ForegroundColor Yellow
}

$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$results = $searcher.Search($UpdateSearchFilter)

$MyUpdates = @()

foreach ($update in $results.Updates) {
  $downloadUrl = $update.BundledUpdates | ForEach-Object {
    $_.DownloadContents | ForEach-Object {
      $_.DownloadUrl
    }
  } | Select-Object -First 1

  $severity = 0
  try {
    $severity = ([int][MsrcSeverity]$update.MsrcSeverity)
  }
  catch {}

  $bulletinId = ($update.SecurityBulletinIDs | Select-Object -First 1)
  $bulletinUrl = if ($bulletinId) {
    'http://www.microsoft.com/technet/security/bulletin/{0}.mspx' -f $bulletinId
  }
  else {
    [System.String]::Empty
  }

  # Create manual download guidance for updates without direct download URLs
  $manualDownloadInfo = ""
  $microsoftCatalogUrl = ""
    
  if (-not $downloadUrl -and $update.KBArticleIDs.Count -gt 0) {
    $kbId = $update.KBArticleIDs | Select-Object -First 1
    $microsoftCatalogUrl = "https://www.catalog.update.microsoft.com/Search.aspx?q=KB$kbId"
    $manualDownloadInfo = "No direct download URL available. Manual download: Microsoft Update Catalog"
  }

  $updates = New-Object -TypeName psobject |
  Add-Member -MemberType NoteProperty -Name Computer -Value "$env:computername" -PassThru -Force |
  Add-Member -MemberType NoteProperty -Name Id -Value ($update.SecurityBulletinIDs | Select-Object -First 1) -PassThru -Force |
  Add-Member -MemberType NoteProperty -Name CVEIds -Value ($update.cveids | Select-Object -First 1) -PassThru -Force |
  Add-Member -MemberType NoteProperty -Name BulletinId -Value $bulletinId -PassThru -Force |
  Add-Member -MemberType NoteProperty -Name KbId -Value ($update.KBArticleIDs | Select-Object -First 1) -PassThru -Force |
  Add-Member -MemberType NoteProperty -Name Type -Value $update.Type -PassThru -Force |
  Add-Member -MemberType NoteProperty -Name IsInstalled -Value $update.IsInstalled -PassThru -Force |
  Add-Member -MemberType NoteProperty -Name InstalledOn -Value $update.LastDeploymentChangeTime -PassThru -Force |
  Add-Member -MemberType NoteProperty -Name RestartRequired -Value $update.RebootRequired -PassThru -Force |
  Add-Member -MemberType NoteProperty -Name Title -Value $update.Title -PassThru -Force |
  Add-Member -MemberType NoteProperty -Name Description -Value $update.Description -PassThru -Force |
  Add-Member -MemberType NoteProperty -Name SeverityText -Value ([MsrcSeverity][int]$severity) -PassThru -Force |
  Add-Member -MemberType NoteProperty -Name Severity -Value $severity -PassThru -ErrorAction SilentlyContinue -Force |
  Add-Member -MemberType NoteProperty -Name InformationURL -Value ($update.MoreInfoUrls | Select-Object -First 1) -PassThru -Force |
  Add-Member -MemberType NoteProperty -Name SupportURL -Value $update.supporturl -PassThru -Force |
  Add-Member -MemberType NoteProperty -Name DownloadURL -Value $downloadUrl -PassThru -Force |
  Add-Member -MemberType NoteProperty -Name ManualDownloadInfo -Value $manualDownloadInfo -PassThru -Force |
  Add-Member -MemberType NoteProperty -Name MicrosoftCatalogURL -Value $microsoftCatalogUrl -PassThru -Force |
  Add-Member -MemberType NoteProperty -Name BulletinURL -Value $bulletinUrl -PassThru -Force

  # Download update if DownloadUpdates switch is enabled and URL is available
  if ($DownloadUpdates -and $downloadUrl) {
    $kbId = $update.KBArticleIDs | Select-Object -First 1
      
    # Store download info for batch processing later
    $updates | Add-Member -MemberType NoteProperty -Name DownloadURL -Value $downloadUrl -Force
    $updates | Add-Member -MemberType NoteProperty -Name KbId -Value $kbId -Force
    $updates | Add-Member -MemberType NoteProperty -Name NeedsDownload -Value $true -Force
  }
  elseif ($DownloadUpdates -and -not $downloadUrl) {
    $kbId = $update.KBArticleIDs | Select-Object -First 1
    $updates | Add-Member -MemberType NoteProperty -Name DownloadSuccess -Value $false -Force
    $updates | Add-Member -MemberType NoteProperty -Name DownloadNote -Value "No direct URL - manual download required" -Force
    $updates | Add-Member -MemberType NoteProperty -Name NeedsDownload -Value $false -Force
    if ($InstallUpdates) {
      $updates | Add-Member -MemberType NoteProperty -Name InstallSuccess -Value $false -Force
    }
  }

  $MyUpdates += $updates
}

# PHASE 1: BATCH DOWNLOAD PROCESSING
if ($DownloadUpdates) {
  $updatesToDownload = $MyUpdates | Where-Object { $_.NeedsDownload -eq $true }
    
  if ($updatesToDownload -and $updatesToDownload.Count -gt 0) {
    Write-Host "`n" + "="*60 -ForegroundColor Green
    Write-Host "STARTING BATCH DOWNLOAD PHASE" -ForegroundColor Green
    Write-Host "="*60 -ForegroundColor Green
    Write-Host "Updates to download: $($updatesToDownload.Count)" -ForegroundColor White
    Write-Host "Download directory: $DownloadPath" -ForegroundColor White
    Write-Host "="*60 -ForegroundColor Green
      
    # Process downloads with progress visualization
    for ($i = 0; $i -lt $updatesToDownload.Count; $i++) {
      $update = $updatesToDownload[$i]
      $currentIndex = $i + 1
        
      $downloadResult = Invoke-UpdateDownload -Url $update.DownloadURL -DestinationPath $DownloadPath -KbId $update.KbId -Title $update.Title -CurrentIndex $currentIndex -TotalCount $updatesToDownload.Count
        
      # Update the original update object with download results
      $originalUpdate = $MyUpdates | Where-Object { $_.KbId -eq $update.KbId }
      $originalUpdate | Add-Member -MemberType NoteProperty -Name DownloadSuccess -Value $downloadResult.Success -Force
      $originalUpdate | Add-Member -MemberType NoteProperty -Name DownloadedFilePath -Value $downloadResult.FilePath -Force
      $originalUpdate | Add-Member -MemberType NoteProperty -Name DownloadedFileSize -Value $downloadResult.FileSize -Force
      $originalUpdate | Add-Member -MemberType NoteProperty -Name DownloadReason -Value $downloadResult.Reason -Force
    }
      
    # Download phase summary
    $successfulDownloads = ($MyUpdates | Where-Object { $_.DownloadSuccess -eq $true }).Count
    $failedDownloads = ($MyUpdates | Where-Object { $_.DownloadSuccess -eq $false -and $_.NeedsDownload -eq $true }).Count
    $totalDownloadSize = ($MyUpdates | Where-Object { $_.DownloadSuccess -eq $true } | Measure-Object -Property DownloadedFileSize -Sum).Sum
    $totalDownloadSizeMB = [math]::Round($totalDownloadSize / 1MB, 2)
      
    Write-Host "`n" + "="*60 -ForegroundColor Green
    Write-Host "DOWNLOAD PHASE COMPLETED" -ForegroundColor Green
    Write-Host "="*60 -ForegroundColor Green
    Write-Host "Successful downloads: $successfulDownloads" -ForegroundColor Green
    Write-Host "Failed downloads: $failedDownloads" -ForegroundColor Red
    Write-Host "Total downloaded: $totalDownloadSizeMB MB" -ForegroundColor Green
    Write-Host "Download directory: $DownloadPath" -ForegroundColor White
    Write-Host "="*60 -ForegroundColor Green
  }
  else {
    Write-Host "`nNo updates available for download (all updates either have no URL or already downloaded)" -ForegroundColor Yellow
  }
}

# PHASE 2: BATCH INSTALLATION PROCESSING
if ($InstallUpdates) {
  $updatesToInstall = $MyUpdates | Where-Object { $_.DownloadSuccess -eq $true -and $_.DownloadedFilePath }
    
  if ($updatesToInstall -and $updatesToInstall.Count -gt 0) {
    Write-Host "`nProceeding with batch installation..." -ForegroundColor Cyan
      
    # Ask for confirmation before installing
    Write-Host "`nWARNING: About to install $($updatesToInstall.Count) Windows Update(s)" -ForegroundColor Yellow
    Write-Host "This may require system restart(s) and could take significant time." -ForegroundColor Yellow
    $confirmation = Read-Host "Do you want to proceed with installation? (Y/N)"
      
    if ($confirmation -eq 'Y' -or $confirmation -eq 'y' -or $confirmation -eq 'Yes') {
      $installResults = Invoke-UpdateBatchInstallation -UpdatesToInstall $updatesToInstall -InstallationMode "Sequential"
        
      # Update the original update objects with installation results
      foreach ($installResult in $installResults) {
        $originalUpdate = $MyUpdates | Where-Object { $_.KbId -eq $installResult.KbId }
        $originalUpdate | Add-Member -MemberType NoteProperty -Name InstallSuccess -Value $installResult.Success -Force
        $originalUpdate | Add-Member -MemberType NoteProperty -Name InstallDuration -Value $installResult.Duration -Force
        $originalUpdate | Add-Member -MemberType NoteProperty -Name InstallationTime -Value $installResult.InstallationTime -Force
      }
    }
    else {
      Write-Host "Installation cancelled by user." -ForegroundColor Yellow
      Write-Host "Updates have been downloaded to: $DownloadPath" -ForegroundColor Cyan
      Write-Host "You can install them manually later or run the script again with -InstallUpdates" -ForegroundColor Cyan
        
      # Mark all as not installed
      $updatesToInstall | ForEach-Object {
        $originalUpdate = $MyUpdates | Where-Object { $_.KbId -eq $_.KbId }
        $originalUpdate | Add-Member -MemberType NoteProperty -Name InstallSuccess -Value $false -Force
        $originalUpdate | Add-Member -MemberType NoteProperty -Name InstallNote -Value "Installation cancelled by user" -Force
      }
    }
  }
  else {
    Write-Host "`nNo updates available for installation (no successfully downloaded updates found)" -ForegroundColor Yellow
  }
}

# Handle updates without direct download URLs
$updatesWithoutUrls = $MyUpdates | Where-Object { $_.NeedsDownload -eq $false -and $null -eq $_.DownloadURL }
if ($DownloadUpdates -and $updatesWithoutUrls -and $updatesWithoutUrls.Count -gt 0) {
  Write-Host "`n" + "="*60 -ForegroundColor Yellow
  Write-Host "MANUAL DOWNLOAD REQUIRED" -ForegroundColor Yellow
  Write-Host "="*60 -ForegroundColor Yellow
  Write-Host "The following $($updatesWithoutUrls.Count) update(s) require manual download:" -ForegroundColor Yellow
    
  foreach ($update in $updatesWithoutUrls) {
    Write-Host "`nKB$($update.KbId): $($update.Title)" -ForegroundColor White
    if ($update.MicrosoftCatalogURL) {
      Write-Host "  Download URL: $($update.MicrosoftCatalogURL)" -ForegroundColor Cyan
    }
    Write-Host "  Alternative: Use Windows Update, WSUS, or manually search Microsoft Update Catalog" -ForegroundColor Gray
  }
    
  Write-Host "`nTip: Visit Microsoft Update Catalog (catalog.update.microsoft.com) for manual downloads" -ForegroundColor Green
  Write-Host "="*60 -ForegroundColor Yellow
}

# Display final summary if downloads were requested
if ($DownloadUpdates) {
  $totalUpdates = $MyUpdates.Count
  $updatesWithUrls = ($MyUpdates | Where-Object { $_.DownloadURL }).Count
  $updatesWithoutUrls = $totalUpdates - $updatesWithUrls
  $successfulDownloads = ($MyUpdates | Where-Object { $_.DownloadSuccess -eq $true }).Count
    
  $summaryTitle = if ($InstallUpdates) { "FINAL DOWNLOAD `& INSTALLATION SUMMARY" } else { "FINAL DOWNLOAD SUMMARY" }
  Write-Host "`n" + "="*60 -ForegroundColor Cyan
  Write-Host $summaryTitle -ForegroundColor Cyan
  Write-Host "="*60 -ForegroundColor Cyan
  Write-Host "Total updates found: $totalUpdates" -ForegroundColor White
  Write-Host "Updates with download URLs: $updatesWithUrls" -ForegroundColor White
  Write-Host "Updates requiring manual download: $updatesWithoutUrls" -ForegroundColor Yellow
  Write-Host "Successful downloads: $successfulDownloads" -ForegroundColor Green
    
  if ($InstallUpdates) {
    $successfulInstallations = ($MyUpdates | Where-Object { $_.InstallSuccess -eq $true }).Count
    $failedInstallations = ($MyUpdates | Where-Object { $_.InstallSuccess -eq $false -and $_.DownloadSuccess -eq $true }).Count
    Write-Host "Successful installations: $successfulInstallations" -ForegroundColor Green
    if ($failedInstallations -gt 0) {
      Write-Host "Failed installations: $failedInstallations" -ForegroundColor Red
    }
  }
    
  Write-Host "Download location: $DownloadPath" -ForegroundColor White
  Write-Host "="*60 -ForegroundColor Cyan
}

# Export report if requested
if ($ExportReport) {
  try {
    $exportPath = $ExportReport
    if (-not $exportPath.EndsWith('.xml')) {
      $exportPath += '.xml'
    }
      
    # Create directory if it doesn't exist
    $exportDir = Split-Path $exportPath -Parent
    if ($exportDir -and -not (Test-Path $exportDir)) {
      New-Item -Path $exportDir -ItemType Directory -Force | Out-Null
      Write-Host "Created export directory: $exportDir" -ForegroundColor Green
    }
      
    Export-Clixml -InputObject $MyUpdates -Path $exportPath -Force
    Write-Host "`nReport exported successfully to: $exportPath" -ForegroundColor Green
    Write-Host "Use this file with -ImportReport parameter on another machine to download updates" -ForegroundColor Yellow
  }
  catch {
    Write-Error "Failed to export report: $($_.Exception.Message)"
  }
}

$MyUpdates