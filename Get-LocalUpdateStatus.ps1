<#
PSScriptInfo

.VERSION 1.0.3

.GUID 4b937790-b06b-427f-8c1f-565030ae0227

.AUTHOR Jan Tiedemann

.COMPANYNAME Jan Tiedemann

.COPYRIGHT 2021

.TAGS Updates, WindowsUpdates

.DESCRIPTION 
Enumerates missing or installed Windows Updates and returns an array of objects with update details.
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
    [System.String]$UpdateSearchFilter
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

    $MyUpdates += $updates
  }

  $MyUpdates
}