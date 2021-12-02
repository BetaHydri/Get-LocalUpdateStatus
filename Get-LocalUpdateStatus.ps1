
<#PSScriptInfo

.VERSION 1.0.2

.GUID 4b937790-b06b-427f-8c1f-565030ae0227

.AUTHOR Jan Tiedemann

.COMPANYNAME Jan Tiedemann

.COPYRIGHT 2021

.TAGS PSScript

.LICENSEURI 

.PROJECTURI 

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES


#>

<# 

.DESCRIPTION 
 Enumerates missing or Installed Windows Updates and returns an array of Objects with updates 

#> 

function Get-LocalUpdateStatus { 
  #requires -Version 4
  <#
    .SYNOPSIS
		Script to search for security updates installed and/or missing
	
    .NOTES
		Jan-Andre Tiedemann
		    
    .DESCRIPTION
		A  script to search for missing software updates without CAB
    
    .PARAMETER 	ComputerName
		The machine as NetBIOS or FQDN
    
    .PARAMETER UpdateSearchFilter
    Predefined ValidateSet

    .EXAMPLE
		Get-LocalUpdateStatus -ComputerName 'Server1'
	
	.EXAMPLE
		Get-LocalUpdateStatus -ComputerName $env:ComputerName -UpdateSearchFilter 'IsHidden=0 and IsInstalled=0'
    
	.OUTPUTS
		System.String. You can pipe it into a Table and wirte it into a csv for further excel processing.
  #>
  [CmdletBinding(DefaultParameterSetName = 'ComputerName')]
  param (
    # Target machine name
    [Parameter(Position = 0, 
      Mandatory = $true, 
      ParameterSetName = 'ComputerName', 
      HelpMessage = "Enter target machine name")]
    [System.String]$ComputerName,

    # Target machines as text file each line one server
    #[Parameter(Position=0, 
    #Mandatory = $true, 
    #ParameterSetName = 'ServerFile', 
    #HelpMessage="Target machines as text file. Each line one server")]
    #[System.String]$Servers_file,

    # UpdateSearchFilter e.g. 'IsHidden=0 and IsInstalled=0' to retrieve 'Missing Updates' including hidden ones.
    [Parameter(Position = 1, 
      Mandatory = $true,
      HelpMessage = "Filter to show e.g. only missing updates 'IsInstalled=0' or all updates 'IsHidden=0'")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet('IsHidden=0 and IsInstalled=0', 'IsHidden=0 and IsInstalled=1', 'IsInstalled=1', 'IsInstalled=0', 'IsHidden=0', 'IsHidden=1')]
    [System.String]$UpdateSearchFilter
	
  )

  #Check is Powershell was opened with Admin privileges
  If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {    
    Write-Host "This script needs to be run As Admin" -ForegroundColor Red
    Write-Host "Furthermore the User should be Admin on each Computer/Server from where you want to gather the WindowsUpdate status !" -ForegroundColor Yellow
    Break
  }

  [void][Reflection.Assembly]::LoadFrom("C:\WINDOWS\Microsoft.NET\Framework\v2.0.50727\Microsoft.VisualBasic.dll") 
  $session = [microsoft.visualbasic.interaction]::CreateObject("Microsoft.Update.Session", $ComputerName) 
  $searcher = $session.CreateUpdateSearcher() 
  $results = $searcher.Search($UpdateSearchFilter)

  # Enum for Severity number property
  Add-Type -TypeDefinition '
  public enum MsrcSeverity {
    Unspecified,
    Low,
    Moderate,
    Important,
    Critical
  } ' -ErrorAction SilentlyContinue
  
  # Array to store Updates Objects
  $MyUpdates = @()

  #$results=Get-LocalUpdateStatus $env:computername
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
    catch { 

    }

    $bulletinId = ($update.SecurityBulletinIDs | Select-Object -First 1)
    $bulletinUrl = if ($bulletinId) {
      'http://www.microsoft.com/technet/security/bulletin/{0}.mspx' -f $bulletinId
    }
    else {
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
