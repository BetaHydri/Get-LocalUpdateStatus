<#
PSScriptInfo

.VERSION 1.1.0

.GUID 4b937790-b06b-427f-8c1f-565030ae0227

.AUTHOR Jan Tiedemann

.COMPANYNAME Jan Tiedemann

.COPYRIGHT 2021

.TAGS Updates, WindowsUpdates, Download

.DESCRIPTION 
Enumerates missing or installed Windows Updates and returns an array of objects with update details. 
Optionally downloads update files when DownloadURL is available.
#>

function Get-LocalUpdateStatus {
  #requires -Version 4
  [CmdletBinding(DefaultParameterSetName = 'ComputerName')]
  param (
    [Parameter(Position = 0, Mandatory = $true, ParameterSetName = 'ComputerName')]
    [System.String]$ComputerName,

    [Parameter(Position = 1, Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidateSet('IsHidden=0 and IsInstalled=0', 'IsHidden=0 and IsInstalled=1', 'IsInstalled=1', 'IsInstalled=0', 'IsHidden=0', 'IsHidden=1')]
    [System.String]$UpdateSearchFilter,

    [Parameter(Position = 2, Mandatory = $false)]
    [Switch]$DownloadUpdates,

    [Parameter(Position = 3, Mandatory = $false)]
    [ValidateScript({
      if ($_ -and -not (Test-Path $_ -PathType Container)) {
        throw "Download path '$_' does not exist or is not a directory."
      }
      return $true
    })]
    [System.String]$DownloadPath = "$env:TEMP\WindowsUpdates"
  )

  # Check for admin privileges
  If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script needs to be run As Admin" -ForegroundColor Red
    Write-Host "Furthermore, the user should be Admin on each computer/server from where you want to gather the Windows Update status!" -ForegroundColor Yellow
    Break
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

  [void][Reflection.Assembly]::LoadFrom("C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.VisualBasic.dll")
  $session = [microsoft.visualbasic.interaction]::CreateObject("Microsoft.Update.Session", $ComputerName)
  $searcher = $session.CreateUpdateSearcher()
  $results = $searcher.Search($UpdateSearchFilter)

  # Enum for Severity
  Add-Type -TypeDefinition '
  public enum MsrcSeverity {
    Unspecified,
    Low,
    Moderate,
    Important,
    Critical
  }' -ErrorAction SilentlyContinue

  # Helper function to download updates
  function Invoke-UpdateDownload {
    param(
      [string]$Url,
      [string]$DestinationPath,
      [string]$KbId,
      [string]$Title
    )
    
    if ([string]::IsNullOrWhiteSpace($Url)) {
      return $false
    }

    try {
      # Extract filename from URL or create one based on KB ID
      $fileName = Split-Path $Url -Leaf
      if ([string]::IsNullOrWhiteSpace($fileName) -or $fileName -notmatch '\.\w+$') {
        $fileName = "KB$KbId.msu"
      }
      
      $fullPath = Join-Path $DestinationPath $fileName
      
      # Check if file already exists
      if (Test-Path $fullPath) {
        Write-Host "  File already exists: $fileName" -ForegroundColor Yellow
        return $true
      }

      Write-Host "  Downloading: $fileName" -ForegroundColor Cyan
      Write-Host "  From: $Url" -ForegroundColor Gray
      
      # Use Invoke-WebRequest for download with progress
      $progressPreference = $global:ProgressPreference
      $global:ProgressPreference = 'Continue'
      
      Invoke-WebRequest -Uri $Url -OutFile $fullPath -UseBasicParsing
      
      $global:ProgressPreference = $progressPreference
      
      if (Test-Path $fullPath) {
        $fileSize = (Get-Item $fullPath).Length
        $fileSizeMB = [math]::Round($fileSize / 1MB, 2)
        Write-Host "  Downloaded successfully: $fileName ($fileSizeMB MB)" -ForegroundColor Green
        return $true
      }
      else {
        Write-Host "  Download failed: File not found after download" -ForegroundColor Red
        return $false
      }
    }
    catch {
      Write-Host "  Download failed: $($_.Exception.Message)" -ForegroundColor Red
      return $false
    }
  }

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
    } catch {}

    $bulletinId = ($update.SecurityBulletinIDs | Select-Object -First 1)
    $bulletinUrl = if ($bulletinId) {
      'http://www.microsoft.com/technet/security/bulletin/{0}.mspx' -f $bulletinId
    } else {
      [System.String]::Empty
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
      Add-Member -MemberType NoteProperty -Name BulletinURL -Value $bulletinUrl -PassThru -Force

    # Download update if DownloadUpdates switch is enabled and URL is available
    if ($DownloadUpdates -and $downloadUrl) {
      $kbId = $update.KBArticleIDs | Select-Object -First 1
      Write-Host "`nProcessing update: KB$kbId - $($update.Title)" -ForegroundColor White
      
      $downloadSuccess = Invoke-UpdateDownload -Url $downloadUrl -DestinationPath $DownloadPath -KbId $kbId -Title $update.Title
      $updates | Add-Member -MemberType NoteProperty -Name DownloadSuccess -Value $downloadSuccess -Force
    }
    elseif ($DownloadUpdates -and -not $downloadUrl) {
      $updates | Add-Member -MemberType NoteProperty -Name DownloadSuccess -Value $false -Force
    }

    $MyUpdates += $updates
  }

  # Display download summary if downloads were requested
  if ($DownloadUpdates) {
    $totalUpdates = $MyUpdates.Count
    $updatesWithUrls = ($MyUpdates | Where-Object { $_.DownloadURL }).Count
    $successfulDownloads = ($MyUpdates | Where-Object { $_.DownloadSuccess -eq $true }).Count
    
    Write-Host "`n" + "="*50 -ForegroundColor Cyan
    Write-Host "DOWNLOAD SUMMARY" -ForegroundColor Cyan
    Write-Host "="*50 -ForegroundColor Cyan
    Write-Host "Total updates found: $totalUpdates" -ForegroundColor White
    Write-Host "Updates with download URLs: $updatesWithUrls" -ForegroundColor White
    Write-Host "Successful downloads: $successfulDownloads" -ForegroundColor Green
    Write-Host "Download location: $DownloadPath" -ForegroundColor White
    Write-Host "="*50 -ForegroundColor Cyan
  }

  $MyUpdates
}