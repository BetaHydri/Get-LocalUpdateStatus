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
      
      # Handle download mode or air-gapped installation for imported data
      if ($DownloadUpdates -or $InstallUpdates) {
        # For air-gapped installation without download, check for existing files
        if ($InstallUpdates -and -not $DownloadUpdates) {
          Write-Host "`nAir-gapped installation mode for imported updates..." -ForegroundColor Cyan
          Write-Host "Searching for pre-downloaded files matching imported updates..." -ForegroundColor Yellow
        } else {
          Write-Host "`nDownload mode enabled for imported updates..." -ForegroundColor Yellow
        }
        
        # Create download directory if it doesn't exist
        if (-not (Test-Path $DownloadPath)) {
          if ($DownloadUpdates) {
            try {
              New-Item -Path $DownloadPath -ItemType Directory -Force | Out-Null
              Write-Host "Created download directory: $DownloadPath" -ForegroundColor Green
            }
            catch {
              Write-Error "Failed to create download directory: $DownloadPath. Error: $($_.Exception.Message)"
              return
            }
          }
