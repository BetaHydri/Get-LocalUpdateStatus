function Test-NewParameters {
  [CmdletBinding(DefaultParameterSetName = 'ComputerName')]
  param (
    [Parameter(Mandatory = $true, ParameterSetName = 'OfflineInstall')]
    [ValidateScript({
        if (-not (Test-Path $_ -PathType Leaf)) {
          throw "Scan report file '$_' does not exist."
        }
        return $true
      })]
    [System.String]$ScanReport,

    [Parameter(Mandatory = $true, ParameterSetName = 'OfflineInstall')]
    [ValidateScript({
        if (-not (Test-Path $_ -PathType Container)) {
          throw "Update files directory '$_' does not exist or is not a directory."
        }
        return $true
      })]
    [System.String]$UpdateFilesPath,

    [Parameter(Mandatory = $false, ParameterSetName = 'OfflineInstall')]
    [Switch]$OfflineInstallOnly
  )
  
  Write-Host "Test successful with parameters:"
  Write-Host "ScanReport: $ScanReport"
  Write-Host "UpdateFilesPath: $UpdateFilesPath"
  Write-Host "OfflineInstallOnly: $OfflineInstallOnly"
}