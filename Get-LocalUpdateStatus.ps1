<#
PSScriptInfo

.VERSION 1.8.4

.GUID 4b937790-b06b-427f-8c1f-565030ae0227

.AUTHOR Jan Tiedemann

.COMPANYNAME Jan Tiedemann

.COPYRIGHT 2025

.TAGS Updates, WindowsUpdates, Download, Export, Import, WSUS, Offline, BatchInstall

.DESCRIPTION 
Enumerates missing or installed Windows Updates on the local computer and returns an array of objects with update details. 
Features enhanced batch download-first-then-install workflow with comprehensive progress visualization.
Supports exporting scan results and importing them on other machines for download.
Supports WSUS offline scanning using wsusscn2.cab for air-gapped environments.
Includes interactive installation confirmation and detailed batch processing summaries.
This function operates on the local computer only - run directly on each machine to be scanned.
#>

# Helper function to install updates (.cab via DISM, .msu via WUSA, .exe via silent execution)
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
  
  # Special handling for Azure Connected Machine Agent
  if ($Title -like "*AzureConnectedMachineAgent*" -or $fileName -like "*azureconnectedmachineagent*") {
    Write-Host "  Detected Azure Connected Machine Agent update - using specialized installation method..." -ForegroundColor Yellow
    
    # For Azure Connected Machine Agent, try direct service-based installation
    try {
      Write-Host "  Stopping Azure Connected Machine Agent services..." -ForegroundColor Gray
      $services = @("himds", "AzureConnectedMachineAgent")
      foreach ($svc in $services) {
        $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq 'Running') {
          Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
          Start-Sleep -Seconds 2
        }
      }
    }
    catch {
      Write-Host "  Warning: Could not stop Azure services: $($_.Exception.Message)" -ForegroundColor Yellow
    }
  }
  
  Write-Host "  Installing: $fileName" -ForegroundColor Cyan
  
  try {
    switch ($fileExtension) {
      '.cab' {
        # Use DISM for .cab files (primary method)
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
        elseif ($process.ExitCode -eq 2) {
          # DISM exit code 2: Invalid command line or access denied
          Write-Host "  DISM failed (exit code 2: Invalid command or access denied), trying alternative method..." -ForegroundColor Yellow
          Write-Host "  DEBUG: Title='$Title', FileName='$fileName'" -ForegroundColor Magenta
          
          # Special handling for Azure Connected Machine Agent (improved detection)
          $isAzureAgent = ($Title -like "*AzureConnectedMachineAgent*") -or 
          ($Title -like "*Azure Connected Machine Agent*") -or
          ($fileName -like "*azureconnectedmachineagent*") -or
          ($fileName -like "*azure*connected*machine*agent*")
          
          Write-Host "  DEBUG: Azure agent detection result: $isAzureAgent" -ForegroundColor Magenta
          
          if ($isAzureAgent) {
            Write-Host "  Azure Connected Machine Agent detected - using specialized extraction..." -ForegroundColor Cyan
            
            # Try using makecab/extract with different parameters for Azure agent
            try {
              $tempDir = Join-Path $env:TEMP "AzureAgent_$([System.Guid]::NewGuid().ToString('N')[0..7] -join '')"
              New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
              
              Write-Host "  Extracting Azure Connected Machine Agent package..." -ForegroundColor Gray
              
              # Try different extraction methods for this specific agent
              $extractSuccess = $false
              
              # Method 1: extrac32.exe (better for SCOM .cab files)
              Write-Host "  Trying extrac32.exe for .cab extraction..." -ForegroundColor Gray
              $extrac32Process = Start-Process -FilePath 'extrac32.exe' -ArgumentList @("/Y", "/E", "/L", $tempDir, $FilePath) -Wait -PassThru -NoNewWindow
              if ($extrac32Process.ExitCode -eq 0) {
                $extractSuccess = $true
                Write-Host "  Extraction successful with extrac32.exe" -ForegroundColor Green
              }
              
              # Method 2: Try expand.exe if extrac32.exe failed
              if (-not $extractSuccess) {
                Write-Host "  extrac32.exe failed, trying expand.exe..." -ForegroundColor Yellow
                $expandProcess = Start-Process -FilePath 'expand.exe' -ArgumentList @("-F:*", $FilePath, $tempDir, "-R") -Wait -PassThru -NoNewWindow
                if ($expandProcess.ExitCode -eq 0) {
                  $extractSuccess = $true
                  Write-Host "  Extraction successful with expand.exe" -ForegroundColor Green
                }
              }
              
              if ($extractSuccess) {
                # Look for any executable content
                Write-Host "  Searching for installable content..." -ForegroundColor Gray
                $allFiles = Get-ChildItem -Path $tempDir -Recurse -File
                Write-Host "  Found $($allFiles.Count) files in extracted content:" -ForegroundColor Gray
                foreach ($file in $allFiles) {
                  Write-Host "    - $($file.Name) ($($file.Extension))" -ForegroundColor DarkGray
                }
                
                # Try to find and install any executable content
                $installSuccess = $false
                
                # Look for .exe files first
                $exeFiles = $allFiles | Where-Object { $_.Extension -eq '.exe' }
                foreach ($exeFile in $exeFiles) {
                  Write-Host "  Attempting to install: $($exeFile.Name)" -ForegroundColor Yellow
                  try {
                    $exeProcess = Start-Process -FilePath $exeFile.FullName -ArgumentList @('/quiet', '/norestart') -Wait -PassThru -NoNewWindow
                    if ($exeProcess.ExitCode -eq 0 -or $exeProcess.ExitCode -eq 3010) {
                      $installSuccess = $true
                      Write-Host "  Installation successful via extracted .exe: $($exeFile.Name)" -ForegroundColor Green
                      break
                    }
                  }
                  catch {
                    Write-Host "  Failed to execute $($exeFile.Name): $($_.Exception.Message)" -ForegroundColor Red
                  }
                }
                
                # If no .exe worked, try .msi files
                if (-not $installSuccess) {
                  $msiFiles = $allFiles | Where-Object { $_.Extension -eq '.msi' }
                  foreach ($msiFile in $msiFiles) {
                    Write-Host "  Attempting to install MSI: $($msiFile.Name)" -ForegroundColor Yellow
                    try {
                      $msiProcess = Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/i', $msiFile.FullName, '/quiet', '/norestart', 'REBOOT=ReallySuppress') -Wait -PassThru -NoNewWindow
                      if ($msiProcess.ExitCode -eq 0 -or $msiProcess.ExitCode -eq 3010 -or $msiProcess.ExitCode -eq 1638) {
                        $installSuccess = $true
                        Write-Host "  Installation successful via extracted .msi: $($msiFile.Name)" -ForegroundColor Green
                        break
                      }
                    }
                    catch {
                      Write-Host "  Failed to execute $($msiFile.Name): $($_.Exception.Message)" -ForegroundColor Red
                    }
                  }
                }
                
                # If no .msi worked, try .msp files (Microsoft Patch files)
                if (-not $installSuccess) {
                  $mspFiles = $allFiles | Where-Object { $_.Extension -eq '.msp' }
                  foreach ($mspFile in $mspFiles) {
                    Write-Host "  Attempting to install MSP patch: $($mspFile.Name)" -ForegroundColor Yellow
                    try {
                      $mspProcess = Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/p', $mspFile.FullName, '/quiet', '/norestart', 'REBOOT=ReallySuppress') -Wait -PassThru -NoNewWindow
                      if ($mspProcess.ExitCode -eq 0 -or $mspProcess.ExitCode -eq 3010 -or $mspProcess.ExitCode -eq 1638) {
                        $installSuccess = $true
                        Write-Host "  Installation successful via extracted .msp: $($mspFile.Name)" -ForegroundColor Green
                        break
                      }
                    }
                    catch {
                      Write-Host "  Failed to execute $($mspFile.Name): $($_.Exception.Message)" -ForegroundColor Red
                    }
                  }
                }
                
                Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                
                if ($installSuccess) {
                  return $true
                }
                else {
                  Write-Host "  Azure Connected Machine Agent installation failed via all extraction methods" -ForegroundColor Red
                  return $false
                }
              }
              else {
                Write-Host "  Failed to extract Azure Connected Machine Agent package" -ForegroundColor Red
                Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                return $false
              }
            }
            catch {
              Write-Host "  Azure Connected Machine Agent specialized installation failed: $($_.Exception.Message)" -ForegroundColor Red
              return $false
            }
          }
          
          # Standard fallback method for other .cab files
          try {
            $tempDir = Join-Path $env:TEMP "CabExtract_$([System.Guid]::NewGuid().ToString('N')[0..7] -join '')"
            New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
            
            Write-Host "  Attempting .cab extraction and manual installation..." -ForegroundColor Gray
            
            # Try extrac32.exe first (better for SCOM .cab files)
            Write-Host "  Trying extrac32.exe for .cab extraction..." -ForegroundColor Gray
            $extrac32Process = Start-Process -FilePath 'extrac32.exe' -ArgumentList @("/Y", "/E", "/L", $tempDir, $FilePath) -Wait -PassThru -NoNewWindow
            
            if ($extrac32Process.ExitCode -eq 0) {
              Write-Host "  Extraction successful with extrac32.exe" -ForegroundColor Green
            }
            else {
              # If extrac32.exe fails, try expand.exe as fallback
              Write-Host "  extrac32.exe failed (exit code: $($extrac32Process.ExitCode)), trying expand.exe..." -ForegroundColor Yellow
              $expandProcess = Start-Process -FilePath 'expand.exe' -ArgumentList @("-F:*", $FilePath, $tempDir) -Wait -PassThru -NoNewWindow
              if ($expandProcess.ExitCode -eq 0) {
                Write-Host "  Extraction successful with expand.exe" -ForegroundColor Green
              }
              else {
                Write-Host "  Both extraction methods failed. extrac32.exe: $($extrac32Process.ExitCode), expand.exe: $($expandProcess.ExitCode)" -ForegroundColor Red
                Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                return $false
              }
            }
            
            # Analysis phase - check what was extracted
            $installationSuccess = $false
            
            # Debug: List all extracted files
            Write-Host "  Analyzing extracted content..." -ForegroundColor Gray
            $allExtractedFiles = Get-ChildItem -Path $tempDir -Recurse -File
            Write-Host "  Found $($allExtractedFiles.Count) files in extracted content:" -ForegroundColor Gray
            foreach ($file in $allExtractedFiles) {
              Write-Host "    - $($file.Name) ($($file.Extension.ToLower())) [$(($file.Length/1KB).ToString('F1')) KB]" -ForegroundColor DarkGray
            }
            
            # Check if this is a SCOM-related update and prioritize .msp files
            $isSCOMUpdate = ($Title -like "*SCOM*") -or 
            ($Title -like "*System Center*") -or
            ($Title -like "*Operations Manager*") -or
            ($fileName -like "*scom*") -or
            ($fileName -like "*mom*")
            
            # For SCOM updates, check .msp files first
            if ($isSCOMUpdate) {
              Write-Host "  SCOM-related update detected - checking for .msp files first..." -ForegroundColor Cyan
              $mspFiles = Get-ChildItem -Path $tempDir -Filter "*.msp" -Recurse
              if ($mspFiles) {
                Write-Host "  Found $($mspFiles.Count) .msp file(s), attempting SCOM installation..." -ForegroundColor Cyan
                
                foreach ($mspFile in $mspFiles) {
                  Write-Host "  Installing SCOM .msp patch: $($mspFile.Name)" -ForegroundColor Gray
                  
                  # Enhanced .msp installation arguments for SCOM Agent
                  $mspArgs = @(
                    '/p'
                    $mspFile.FullName
                    '/quiet'
                    '/norestart'
                    'REBOOT=ReallySuppress'
                    'ALLUSERS=1'
                    '/l*v'
                    (Join-Path $env:TEMP "SCOM_MSP_Extract_$([System.Guid]::NewGuid().ToString('N')[0..7] -join '').log")
                  )
                  
                  $mspProcess = Start-Process -FilePath 'msiexec.exe' -ArgumentList $mspArgs -Wait -PassThru -NoNewWindow
                  
                  if ($mspProcess.ExitCode -eq 0) {
                    $installationSuccess = $true
                    Write-Host "  SCOM installation successful via extracted .msp: $($mspFile.Name)" -ForegroundColor Green
                    break
                  }
                  elseif ($mspProcess.ExitCode -eq 3010) {
                    $installationSuccess = $true
                    Write-Host "  SCOM installation successful (restart required): $($mspFile.Name)" -ForegroundColor Yellow
                    break
                  }
                  elseif ($mspProcess.ExitCode -eq 1638) {
                    $installationSuccess = $true
                    Write-Host "  SCOM patch already applied: $($mspFile.Name)" -ForegroundColor Yellow
                    break
                  }
                  elseif ($mspProcess.ExitCode -eq 1605) {
                    Write-Host "  SCOM .msp installation failed: No products found to patch - $($mspFile.Name)" -ForegroundColor Red
                    Write-Host "  This indicates the SCOM Agent is not installed or the patch is not applicable" -ForegroundColor Yellow
                  }
                  elseif ($mspProcess.ExitCode -eq 1619) {
                    Write-Host "  SCOM .msp installation failed: Package couldn't be opened - $($mspFile.Name)" -ForegroundColor Red
                    Write-Host "  Verify the .msp file integrity and permissions" -ForegroundColor Yellow
                  }
                  else {
                    Write-Host "  SCOM .msp installation failed (Exit code: $($mspProcess.ExitCode)): $($mspFile.Name)" -ForegroundColor Red
                    $logFile = $mspArgs | Where-Object { $_ -like "*.log" }
                    if ($logFile -and (Test-Path $logFile)) {
                      Write-Host "  Check SCOM installation log for details: $logFile" -ForegroundColor Cyan
                    }
                  }
                }
                
                if (-not $installationSuccess) {
                  Write-Host "  SCOM Agent patch installation failed. Common issues:" -ForegroundColor Yellow
                  Write-Host "    - Ensure SCOM Agent is installed before applying patches" -ForegroundColor Gray
                  Write-Host "    - Check if the patch matches the installed SCOM Agent version" -ForegroundColor Gray
                  Write-Host "    - Verify Administrator privileges" -ForegroundColor Gray
                  Write-Host "    - Check Windows Event Log for additional error details" -ForegroundColor Gray
                }
              }
              else {
                Write-Host "  No .msp files found in .cab file." -ForegroundColor Yellow
              }
            }
            
            # Look for .msu files in extracted content (if not SCOM or SCOM .msp failed)
            if (-not $installationSuccess) {
              $msuFiles = Get-ChildItem -Path $tempDir -Filter "*.msu" -Recurse
              if ($msuFiles) {
                Write-Host "  Found $($msuFiles.Count) .msu file(s), attempting installation..." -ForegroundColor Cyan
                foreach ($msuFile in $msuFiles) {
                  Write-Host "  Installing .msu file: $($msuFile.Name)" -ForegroundColor Gray
                  $wusaProcess = Start-Process -FilePath 'wusa.exe' -ArgumentList @($msuFile.FullName, '/quiet', '/norestart') -Wait -PassThru -NoNewWindow
                  if ($wusaProcess.ExitCode -eq 0 -or $wusaProcess.ExitCode -eq 3010) {
                    $installationSuccess = $true
                    Write-Host "  Installation successful via extracted .msu: $fileName" -ForegroundColor Green
                    break
                  }
                }
              }
            }
            
            # Look for .msi files in extracted content if .msu installation failed
            if (-not $installationSuccess) {
              $msiFiles = Get-ChildItem -Path $tempDir -Filter "*.msi" -Recurse
              if ($msiFiles) {
                Write-Host "  Found $($msiFiles.Count) .msi file(s), attempting installation..." -ForegroundColor Cyan
                foreach ($msiFile in $msiFiles) {
                  Write-Host "  Installing .msi file: $($msiFile.Name)" -ForegroundColor Gray
                  $msiArgs = @(
                    '/i'
                    $msiFile.FullName
                    '/quiet'
                    '/norestart'
                    'REBOOT=ReallySuppress'
                  )
                    
                  $msiProcess = Start-Process -FilePath 'msiexec.exe' -ArgumentList $msiArgs -Wait -PassThru -NoNewWindow
                  if ($msiProcess.ExitCode -eq 0) {
                    $installationSuccess = $true
                    Write-Host "  Installation successful via extracted .msi: $fileName" -ForegroundColor Green
                    break
                  }
                  elseif ($msiProcess.ExitCode -eq 3010) {
                    $installationSuccess = $true
                    Write-Host "  Installation successful via extracted .msi (restart required): $fileName" -ForegroundColor Yellow
                    break
                  }
                  elseif ($msiProcess.ExitCode -eq 1638) {
                    $installationSuccess = $true
                    Write-Host "  Installation skipped: Product already installed - $fileName" -ForegroundColor Yellow
                    break
                  }
                  else {
                    Write-Host "  .msi installation failed (Exit code: $($msiProcess.ExitCode)): $($msiFile.Name)" -ForegroundColor Red
                  }
                }
              }
                
              # Look for .msp files (Microsoft Patch files) if .msi installation failed
              if (-not $installationSuccess) {
                $mspFiles = Get-ChildItem -Path $tempDir -Filter "*.msp" -Recurse
                if ($mspFiles) {
                  Write-Host "  Found $($mspFiles.Count) .msp file(s), attempting installation..." -ForegroundColor Cyan
                  
                  # Check if this is a SCOM Agent related patch
                  $isSCOMPatch = ($Title -like "*SCOM*") -or 
                  ($Title -like "*System Center Operations Manager*") -or
                  ($Title -like "*Operations Manager*") -or
                  ($fileName -like "*scom*") -or
                  ($fileName -like "*mom*") -or
                  ($mspFiles | Where-Object { $_.Name -like "*scom*" -or $_.Name -like "*mom*" -or $_.Name -like "*opsmgr*" })
                  
                  if ($isSCOMPatch) {
                    Write-Host "  SCOM Agent patch detected - using enhanced installation method..." -ForegroundColor Yellow
                  }
                  
                  foreach ($mspFile in $mspFiles) {
                    Write-Host "  Installing .msp patch: $($mspFile.Name)" -ForegroundColor Gray
                    
                    # Enhanced .msp installation arguments for SCOM Agent
                    $mspArgs = if ($isSCOMPatch) {
                      @(
                        '/p'
                        $mspFile.FullName
                        '/quiet'
                        '/norestart'
                        'REBOOT=ReallySuppress'
                        'ALLUSERS=1'
                        '/l*v'
                        (Join-Path $env:TEMP "SCOM_MSP_Install_$([System.Guid]::NewGuid().ToString('N')[0..7] -join '').log")
                      )
                    }
                    else {
                      @(
                        '/p'
                        $mspFile.FullName
                        '/quiet'
                        '/norestart'
                        'REBOOT=ReallySuppress'
                      )
                    }
                      
                    $mspProcess = Start-Process -FilePath 'msiexec.exe' -ArgumentList $mspArgs -Wait -PassThru -NoNewWindow
                    
                    # Enhanced exit code handling for .msp files
                    if ($mspProcess.ExitCode -eq 0) {
                      $installationSuccess = $true
                      Write-Host "  Installation successful via extracted .msp: $($mspFile.Name)" -ForegroundColor Green
                      break
                    }
                    elseif ($mspProcess.ExitCode -eq 3010) {
                      $installationSuccess = $true
                      Write-Host "  Installation successful via extracted .msp (restart required): $($mspFile.Name)" -ForegroundColor Yellow
                      break
                    }
                    elseif ($mspProcess.ExitCode -eq 1638) {
                      $installationSuccess = $true
                      Write-Host "  Installation skipped: Patch already applied - $($mspFile.Name)" -ForegroundColor Yellow
                      break
                    }
                    elseif ($mspProcess.ExitCode -eq 1605) {
                      Write-Host "  .msp installation failed: No products found to patch - $($mspFile.Name)" -ForegroundColor Red
                      Write-Host "  This may indicate the base product (SCOM Agent) is not installed or the patch is not applicable" -ForegroundColor Yellow
                    }
                    elseif ($mspProcess.ExitCode -eq 1619) {
                      Write-Host "  .msp installation failed: Package couldn't be opened - $($mspFile.Name)" -ForegroundColor Red
                      Write-Host "  Verify the .msp file integrity and permissions" -ForegroundColor Yellow
                    }
                    elseif ($mspProcess.ExitCode -eq 1636) {
                      Write-Host "  .msp installation failed: Patch package couldn't be opened - $($mspFile.Name)" -ForegroundColor Red
                    }
                    elseif ($mspProcess.ExitCode -eq 1633) {
                      Write-Host "  .msp installation failed: Platform not supported - $($mspFile.Name)" -ForegroundColor Red
                    }
                    else {
                      Write-Host "  .msp installation failed (Exit code: $($mspProcess.ExitCode)): $($mspFile.Name)" -ForegroundColor Red
                      if ($isSCOMPatch) {
                        $logFile = $mspArgs | Where-Object { $_ -like "*.log" }
                        if ($logFile -and (Test-Path $logFile)) {
                          Write-Host "  Check SCOM installation log for details: $logFile" -ForegroundColor Cyan
                        }
                      }
                    }
                  }
                  
                  # If SCOM patch failed, provide additional guidance
                  if (-not $installationSuccess -and $isSCOMPatch) {
                    Write-Host "  SCOM Agent patch installation failed. Common issues:" -ForegroundColor Yellow
                    Write-Host "    - Ensure SCOM Agent is installed before applying patches" -ForegroundColor Gray
                    Write-Host "    - Check if the patch matches the installed SCOM Agent version" -ForegroundColor Gray
                    Write-Host "    - Verify Administrator privileges" -ForegroundColor Gray
                    Write-Host "    - Check Windows Event Log for additional error details" -ForegroundColor Gray
                  }
                }
              }
            }
              
            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
              
            if ($installationSuccess) {
              return $true
            }
            else {
              # Check if this looks like a SCOM-related update for enhanced error messaging
              $isSCOMRelated = ($Title -like "*SCOM*") -or 
              ($Title -like "*System Center*") -or
              ($Title -like "*Operations Manager*") -or
              ($fileName -like "*scom*")
              
              Write-Host "  No installable content found in extracted .cab file: $fileName" -ForegroundColor Red
              
              if ($isSCOMRelated) {
                Write-Host "  SCOM Agent update detected. Common issues:" -ForegroundColor Yellow
                Write-Host "    - Ensure SCOM Agent is installed before applying updates" -ForegroundColor Gray
                Write-Host "    - Check if this update is applicable to your SCOM Agent version" -ForegroundColor Gray
                Write-Host "    - Some SCOM updates require specific prerequisites" -ForegroundColor Gray
                Write-Host "    - Verify the .cab file contains the expected .msp files" -ForegroundColor Gray
              }
              else {
                Write-Host "  The .cab file may require manual installation or specific prerequisites" -ForegroundColor Yellow
              }
              
              return $false
            }
            
            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "  Alternative installation methods failed: $fileName" -ForegroundColor Red
            return $false
          }
          catch {
            Write-Host "  Alternative installation failed with error: $($_.Exception.Message)" -ForegroundColor Red
            return $false
          }
        }
        if ($process.ExitCode -eq 50) {
          Write-Host "  Installation skipped: Package not applicable to this system - $fileName" -ForegroundColor Yellow
          return $true
        }
        elseif ($process.ExitCode -eq 87) {
          Write-Host "  Installation failed: Invalid parameter - $fileName (Exit code: 87)" -ForegroundColor Red
          return $false
        }
        elseif ($process.ExitCode -eq 1460) {
          Write-Host "  Installation failed: Package already installed - $fileName" -ForegroundColor Yellow
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
      
      '.exe' {
        # Use direct execution for .exe files with silent installation switches
        Write-Host "  Using silent execution for .exe installation..." -ForegroundColor Gray
        
        # Common silent switches for Microsoft executable updates
        $exeArgs = @()
        
        # Try to determine appropriate silent switches based on filename/title
        if ($fileName -match "malicious|removal|tool|msrt" -or $Title -match "Malicious Software Removal Tool") {
          # Windows Malicious Software Removal Tool uses /Q
          $exeArgs = @('/Q')
          Write-Host "  Detected Malicious Software Removal Tool - using /Q switch" -ForegroundColor Gray
        }
        elseif ($fileName -match "defender|antimalware" -or $Title -match "Defender|Antimalware") {
          # Windows Defender updates often use /q
          $exeArgs = @('/q')
          Write-Host "  Detected Defender/Antimalware update - using /q switch" -ForegroundColor Gray
        }
        else {
          # Generic Microsoft executable updates - try common silent switches
          $exeArgs = @('/quiet')
          Write-Host "  Using generic silent switch: /quiet" -ForegroundColor Gray
        }
        
        $process = Start-Process -FilePath $FilePath -ArgumentList $exeArgs -Wait -PassThru -NoNewWindow
        
        if ($process.ExitCode -eq 0) {
          Write-Host "  Installation successful: $fileName" -ForegroundColor Green
          return $true
        }
        elseif ($process.ExitCode -eq 3010) {
          Write-Host "  Installation successful (restart required): $fileName" -ForegroundColor Yellow
          return $true
        }
        elseif ($process.ExitCode -eq 1) {
          Write-Host "  Installation completed with warnings: $fileName" -ForegroundColor Yellow
          return $true
        }
        else {
          Write-Host "  Installation failed: $fileName (Exit code: $($process.ExitCode))" -ForegroundColor Red
          Write-Host "  Note: Some .exe files may require specific switches or manual installation" -ForegroundColor Gray
          return $false
        }
      }
      
      '.msi' {
        # Use msiexec for .msi files
        Write-Host "  Using msiexec for .msi installation..." -ForegroundColor Gray
        $msiArgs = @(
          '/i'
          $FilePath
          '/quiet'
          '/norestart'
          'REBOOT=ReallySuppress'
        )
        
        $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $msiArgs -Wait -PassThru -NoNewWindow
        
        if ($process.ExitCode -eq 0) {
          Write-Host "  Installation successful: $fileName" -ForegroundColor Green
          return $true
        }
        elseif ($process.ExitCode -eq 3010) {
          Write-Host "  Installation successful (restart required): $fileName" -ForegroundColor Yellow
          return $true
        }
        elseif ($process.ExitCode -eq 1638) {
          Write-Host "  Installation skipped: Product already installed - $fileName" -ForegroundColor Yellow
          return $true
        }
        elseif ($process.ExitCode -eq 1605) {
          Write-Host "  Installation failed: This action is only valid for products that are currently installed - $fileName" -ForegroundColor Red
          return $false
        }
        elseif ($process.ExitCode -eq 1619) {
          Write-Host "  Installation failed: Package could not be opened - $fileName" -ForegroundColor Red
          return $false
        }
        elseif ($process.ExitCode -eq 1633) {
          Write-Host "  Installation failed: Platform not supported - $fileName" -ForegroundColor Red
          return $false
        }
        else {
          Write-Host "  Installation failed: $fileName (Exit code: $($process.ExitCode))" -ForegroundColor Red
          Write-Host "  Note: MSI error codes can indicate specific installation issues" -ForegroundColor Gray
          return $false
        }
      }
      
      '.msp' {
        # Use msiexec for .msp files (Microsoft Patch files)
        Write-Host "  Using msiexec for .msp patch installation..." -ForegroundColor Gray
        
        # Check if this is a SCOM Agent related patch
        $isSCOMPatch = ($Title -like "*SCOM*") -or 
        ($Title -like "*System Center Operations Manager*") -or
        ($Title -like "*Operations Manager*") -or
        ($fileName -like "*scom*") -or
        ($fileName -like "*mom*") -or
        ($fileName -like "*opsmgr*")
        
        if ($isSCOMPatch) {
          Write-Host "  SCOM Agent patch detected - using enhanced installation method..." -ForegroundColor Yellow
        }
        
        # Enhanced .msp installation arguments for SCOM Agent
        $mspArgs = if ($isSCOMPatch) {
          @(
            '/p'
            $FilePath
            '/quiet'
            '/norestart'
            'REBOOT=ReallySuppress'
            'ALLUSERS=1'
            '/l*v'
            (Join-Path $env:TEMP "SCOM_MSP_Direct_$([System.Guid]::NewGuid().ToString('N')[0..7] -join '').log")
          )
        }
        else {
          @(
            '/p'
            $FilePath
            '/quiet'
            '/norestart'
            'REBOOT=ReallySuppress'
          )
        }
        
        $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $mspArgs -Wait -PassThru -NoNewWindow
        
        # Enhanced exit code handling for .msp files
        if ($process.ExitCode -eq 0) {
          Write-Host "  Installation successful: $fileName" -ForegroundColor Green
          return $true
        }
        elseif ($process.ExitCode -eq 3010) {
          Write-Host "  Installation successful (restart required): $fileName" -ForegroundColor Yellow
          return $true
        }
        elseif ($process.ExitCode -eq 1638) {
          Write-Host "  Installation skipped: Patch already applied - $fileName" -ForegroundColor Yellow
          return $true
        }
        elseif ($process.ExitCode -eq 1605) {
          Write-Host "  Installation failed: No products found to patch - $fileName" -ForegroundColor Red
          if ($isSCOMPatch) {
            Write-Host "  This may indicate the SCOM Agent is not installed or the patch is not applicable" -ForegroundColor Yellow
          }
          return $false
        }
        elseif ($process.ExitCode -eq 1619) {
          Write-Host "  Installation failed: Package couldn't be opened - $fileName" -ForegroundColor Red
          Write-Host "  Verify the .msp file integrity and permissions" -ForegroundColor Yellow
          return $false
        }
        elseif ($process.ExitCode -eq 1636) {
          Write-Host "  Installation failed: Patch package couldn't be opened - $fileName" -ForegroundColor Red
          return $false
        }
        elseif ($process.ExitCode -eq 1633) {
          Write-Host "  Installation failed: Platform not supported - $fileName" -ForegroundColor Red
          return $false
        }
        else {
          Write-Host "  Installation failed: $fileName (Exit code: $($process.ExitCode))" -ForegroundColor Red
          if ($isSCOMPatch) {
            $logFile = $mspArgs | Where-Object { $_ -like "*.log" }
            if ($logFile -and (Test-Path $logFile)) {
              Write-Host "  Check SCOM installation log for details: $logFile" -ForegroundColor Cyan
            }
            Write-Host "  SCOM Agent patch installation failed. Common issues:" -ForegroundColor Yellow
            Write-Host "    - Ensure SCOM Agent is installed before applying patches" -ForegroundColor Gray
            Write-Host "    - Check if the patch matches the installed SCOM Agent version" -ForegroundColor Gray
            Write-Host "    - Verify Administrator privileges" -ForegroundColor Gray
            Write-Host "    - Check Windows Event Log for additional error details" -ForegroundColor Gray
          }
          return $false
        }
        else {
          Write-Host "  Installation failed: $fileName (Exit code: $($process.ExitCode))" -ForegroundColor Red
          if ($isSCOMPatch) {
            $logFile = $mspArgs | Where-Object { $_ -like "*.log" }
            if ($logFile -and (Test-Path $logFile)) {
              Write-Host "  Check SCOM installation log for details: $logFile" -ForegroundColor Cyan
            }
            Write-Host "  SCOM Agent patch installation failed. Common issues:" -ForegroundColor Yellow
            Write-Host "    - Ensure SCOM Agent is installed before applying patches" -ForegroundColor Gray
            Write-Host "    - Check if the patch matches the installed SCOM Agent version" -ForegroundColor Gray
            Write-Host "    - Verify Administrator privileges" -ForegroundColor Gray
            Write-Host "    - Check Windows Event Log for additional error details" -ForegroundColor Gray
          }
          return $false
        }
      }
      
      default {
        Write-Host "  Installation failed: Unsupported file type '$fileExtension' for $fileName" -ForegroundColor Red
        Write-Host "  Supported types: .cab (DISM), .msu (WUSA), .msi (msiexec), .msp (msiexec), .exe (Silent)" -ForegroundColor Gray
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

  Write-Host ("`n" + "=" * 60) -ForegroundColor Magenta
  Write-Host "STARTING BATCH INSTALLATION" -ForegroundColor Magenta
  Write-Host ("=" * 60) -ForegroundColor Magenta
  Write-Host "Mode: $InstallationMode" -ForegroundColor White
  Write-Host "Total updates to install: $totalUpdates" -ForegroundColor White
  Write-Host ("=" * 60) -ForegroundColor Magenta

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
  Write-Host ("`n" + "=" * 60) -ForegroundColor Magenta
  Write-Host "BATCH INSTALLATION COMPLETED" -ForegroundColor Magenta
  Write-Host ("=" * 60) -ForegroundColor Magenta
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
  
  Write-Host ("`n" + "=" * 60) -ForegroundColor Magenta
  
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
  [CmdletBinding(DefaultParameterSetName = 'LocalScan')]
  param (
    [Parameter(Position = 0, Mandatory = $true, ParameterSetName = 'LocalScan')]
    [Parameter(Position = 0, Mandatory = $true, ParameterSetName = 'WSUSOfflineScan')]
    [ValidateNotNullOrEmpty()]
    [ValidateSet('IsHidden=0 and IsInstalled=0', 'IsHidden=0 and IsInstalled=1', 'IsInstalled=1', 'IsInstalled=0', 'IsHidden=0', 'IsHidden=1')]
    [System.String]$UpdateSearchFilter,

    [Parameter(Position = 1, Mandatory = $false)]
    [Switch]$DownloadUpdates,

    [Parameter(Position = 2, Mandatory = $false)]
    [Switch]$InstallUpdates,

    [Parameter(Position = 3, Mandatory = $false)]
    [ValidateScript({
        if ($_ -and -not (Test-Path $_ -PathType Container)) {
          throw "Download path '$_' does not exist or is not a directory."
        }
        return $true
      })]
    [System.String]$DownloadPath = "$env:TEMP\WindowsUpdates",

    [Parameter(Position = 4, Mandatory = $false)]
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

    [Parameter(Position = 2, Mandatory = $false, ParameterSetName = 'WSUSOfflineScan')]
    [ValidateScript({
        if ($_) {
          # If it's an existing .cab file, use it directly
          if (Test-Path $_ -PathType Leaf -Filter "*.cab") {
            return $true
          }
          # If it's a directory, we'll download wsusscn2.cab there
          elseif (Test-Path $_ -PathType Container) {
            return $true
          }
          # If it doesn't exist but parent directory exists, we can create it
          elseif (Test-Path (Split-Path $_ -Parent)) {
            return $true
          }
          else {
            throw "Path '$_' is not a valid file or directory, and parent directory doesn't exist."
          }
        }
        return $true
      })]
    [System.String]$WSUSScanFile = "$env:TEMP"
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
            # Check if file already exists in download directory
            $fileName = [System.IO.Path]::GetFileName($update.DownloadURL)
            $fullPath = Join-Path $DownloadPath $fileName
            
            if (Test-Path $fullPath) {
              # File already exists - set properties for installation
              $existingSize = (Get-Item $fullPath).Length
              $update | Add-Member -MemberType NoteProperty -Name NeedsDownload -Value $false -Force
              $update | Add-Member -MemberType NoteProperty -Name DownloadSuccess -Value $true -Force
              $update | Add-Member -MemberType NoteProperty -Name DownloadedFilePath -Value $fullPath -Force
              $update | Add-Member -MemberType NoteProperty -Name DownloadedFileSize -Value $existingSize -Force
              $update | Add-Member -MemberType NoteProperty -Name DownloadReason -Value "File already existed" -Force
            }
            else {
              # File needs to be downloaded
              $update | Add-Member -MemberType NoteProperty -Name NeedsDownload -Value $true -Force
            }
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
          Write-Host ("`n" + "=" * 60) -ForegroundColor Green
          Write-Host "STARTING BATCH DOWNLOAD PHASE (IMPORT MODE)" -ForegroundColor Green
          Write-Host ("=" * 60) -ForegroundColor Green
          Write-Host "Updates to download: $($updatesToDownload.Count)" -ForegroundColor White
          Write-Host "Download directory: $DownloadPath" -ForegroundColor White
          Write-Host ("=" * 60) -ForegroundColor Green
          
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
          
          Write-Host ("`n" + "=" * 60) -ForegroundColor Green
          Write-Host "DOWNLOAD PHASE COMPLETED (IMPORT MODE)" -ForegroundColor Green
          Write-Host ("=" * 60) -ForegroundColor Green
          Write-Host "Successful downloads: $successfulDownloads" -ForegroundColor Green
          Write-Host "Failed downloads: $failedDownloads" -ForegroundColor Red
          Write-Host "Total downloaded: $totalDownloadSizeMB MB" -ForegroundColor Green
          Write-Host "Download directory: $DownloadPath" -ForegroundColor White
          Write-Host ("=" * 60) -ForegroundColor Green
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
          Write-Host ("`n" + "=" * 60) -ForegroundColor Yellow
          Write-Host "MANUAL DOWNLOAD REQUIRED (IMPORT MODE)" -ForegroundColor Yellow
          Write-Host ("=" * 60) -ForegroundColor Yellow
          Write-Host "The following $($updatesWithoutUrls.Count) update(s) require manual download:" -ForegroundColor Yellow
          
          foreach ($update in $updatesWithoutUrls) {
            Write-Host "`nKB$($update.KbId): $($update.Title)" -ForegroundColor White
            if ($update.MicrosoftCatalogURL) {
              Write-Host "  Download URL: $($update.MicrosoftCatalogURL)" -ForegroundColor Cyan
            }
            Write-Host "  Alternative: Use Windows Update, WSUS, or manually search Microsoft Update Catalog" -ForegroundColor Gray
          }
          
          Write-Host "`nTip: Visit Microsoft Update Catalog (catalog.update.microsoft.com) for manual downloads" -ForegroundColor Green
          Write-Host ("=" * 60) -ForegroundColor Yellow
        }
        
        # Display final summary for import mode
        $totalUpdates = $MyUpdates.Count
        $updatesWithUrls = ($MyUpdates | Where-Object { $_.DownloadURL }).Count
        $successfulDownloads = ($MyUpdates | Where-Object { $_.DownloadSuccess -eq $true }).Count
        
        $summaryTitle = if ($InstallUpdates) { "FINAL IMPORT, DOWNLOAD & INSTALLATION SUMMARY" } else { "FINAL IMPORT & DOWNLOAD SUMMARY" }
        Write-Host ("`n" + "=" * 60) -ForegroundColor Cyan
        Write-Host $summaryTitle -ForegroundColor Cyan
        Write-Host ("=" * 60) -ForegroundColor Cyan
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
        Write-Host ("=" * 60) -ForegroundColor Cyan
        
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
    
    $scanFile = $null
    
    # Determine if WSUSScanFile is an existing .cab file or a directory
    if ($WSUSScanFile -and (Test-Path $WSUSScanFile -PathType Leaf) -and $WSUSScanFile.EndsWith('.cab')) {
      # Use existing .cab file
      $scanFile = $WSUSScanFile
      Write-Host "Using existing WSUS scan file: $scanFile" -ForegroundColor Green
    }
    else {
      # Download wsusscn2.cab to the specified directory (or temp)
      $downloadPath = if (Test-Path $WSUSScanFile -PathType Container) { $WSUSScanFile } else { $WSUSScanFile }
      
      if (-not (Test-Path $downloadPath)) {
        try {
          New-Item -Path $downloadPath -ItemType Directory -Force | Out-Null
        }
        catch {
          Write-Error "Failed to create download directory: $downloadPath. Error: $($_.Exception.Message)"
          return
        }
      }
      
      $scanFile = Get-WSUSScanFile -DownloadPath $downloadPath
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
        
        # If we found 0 updates, this could be normal (system is up to date) or indicate an issue
        if ($results.Updates.Count -eq 0) {
          # Only show additional diagnostic info if this might be an error condition
          # For missing updates (IsInstalled=0), zero results usually means system is up to date
          if ($UpdateSearchFilter -match "IsInstalled=0") {
            Write-Host "No missing updates found - system appears to be up to date!" -ForegroundColor Green
          }
          else {
            # For other filters, do a quick validation
            Write-Host "No updates found with current filter. Validating scan file..." -ForegroundColor Yellow
            $testResults = $searcher.Search("1=1")  # Search for all updates
            
            if ($testResults.Updates.Count -eq 0) {
              Write-Warning "The wsusscn2.cab file appears to be empty or invalid. Try downloading a fresh copy."
            }
            else {
              Write-Host "The scan file contains $($testResults.Updates.Count) total updates, but none match your filter criteria." -ForegroundColor Cyan
            }
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
            if ($UpdateSearchFilter -match "and" -and $UpdateSearchFilter -match "IsInstalled=0") {
              Write-Host "Compound filters may not be fully supported in WSUS offline mode." -ForegroundColor Yellow
              Write-Host "Try using simplified filter 'IsInstalled=0' instead of '$UpdateSearchFilter'" -ForegroundColor Cyan
              Write-Host "Note: If no missing updates are found, your system is up to date!" -ForegroundColor Green
            }
            else {
              Write-Error "Invalid search filter: $UpdateSearchFilter"
            }
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
          Write-Host ("`n" + "=" * 60) -ForegroundColor Green
          Write-Host "STARTING BATCH DOWNLOAD PHASE (WSUS OFFLINE)" -ForegroundColor Green
          Write-Host ("=" * 60) -ForegroundColor Green
          Write-Host "Updates to download: $($updatesToDownload.Count)" -ForegroundColor White
          Write-Host "Download directory: $DownloadPath" -ForegroundColor White
          Write-Host ("=" * 60) -ForegroundColor Green
          
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
          
          Write-Host ("`n" + "=" * 60) -ForegroundColor Green
          Write-Host "DOWNLOAD PHASE COMPLETED (WSUS OFFLINE)" -ForegroundColor Green
          Write-Host ("=" * 60) -ForegroundColor Green
          Write-Host "Successful downloads: $successfulDownloads" -ForegroundColor Green
          Write-Host "Failed downloads: $failedDownloads" -ForegroundColor Red
          Write-Host "Total downloaded: $totalDownloadSizeMB MB" -ForegroundColor Green
          Write-Host "Download directory: $DownloadPath" -ForegroundColor White
          Write-Host ("=" * 60)-ForegroundColor Green
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
        Write-Host ("`n" + "=" * 60) -ForegroundColor Yellow
        Write-Host "MANUAL DOWNLOAD REQUIRED (WSUS OFFLINE)" -ForegroundColor Yellow
        Write-Host ("=" * 60) -ForegroundColor Yellow
        Write-Host "The following $($updatesWithoutUrls.Count) update(s) require manual download:" -ForegroundColor Yellow
        
        foreach ($update in $updatesWithoutUrls) {
          Write-Host "`nKB$($update.KbId): $($update.Title)" -ForegroundColor White
          if ($update.MicrosoftCatalogURL) {
            Write-Host "  Download URL: $($update.MicrosoftCatalogURL)" -ForegroundColor Cyan
          }
          Write-Host "  Alternative: Use Windows Update, WSUS, or manually search Microsoft Update Catalog" -ForegroundColor Gray
        }
        
        Write-Host "`nTip: Visit Microsoft Update Catalog (catalog.update.microsoft.com) for manual downloads" -ForegroundColor Green
        Write-Host ("=" * 60) -ForegroundColor Yellow
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
      
      $summaryTitle = if ($InstallUpdates) { "FINAL WSUS OFFLINE SCAN, DOWNLOAD & INSTALLATION SUMMARY" } else { "FINAL WSUS OFFLINE SCAN SUMMARY" }
      Write-Host ("`n" + "=" * 60) -ForegroundColor Cyan
      Write-Host $summaryTitle -ForegroundColor Cyan
      Write-Host ("=" * 60) -ForegroundColor Cyan
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
      
      Write-Host ("=" * 60) -ForegroundColor Cyan
      
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
      Write-Host ("`n" + "=" * 60) -ForegroundColor Green
      Write-Host "STARTING BATCH DOWNLOAD PHASE" -ForegroundColor Green
      Write-Host ("=" * 60) -ForegroundColor Green
      Write-Host "Updates to download: $($updatesToDownload.Count)" -ForegroundColor White
      Write-Host "Download directory: $DownloadPath" -ForegroundColor White
      Write-Host ("=" * 60) -ForegroundColor Green
      
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
      
      Write-Host ("`n" + "=" * 60) -ForegroundColor Green
      Write-Host "DOWNLOAD PHASE COMPLETED" -ForegroundColor Green
      Write-Host ("=" * 60) -ForegroundColor Green
      Write-Host "Successful downloads: $successfulDownloads" -ForegroundColor Green
      Write-Host "Failed downloads: $failedDownloads" -ForegroundColor Red
      Write-Host "Total downloaded: $totalDownloadSizeMB MB" -ForegroundColor Green
      Write-Host "Download directory: $DownloadPath" -ForegroundColor White
      Write-Host ("=" * 60) -ForegroundColor Green
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
    Write-Host ("`n" + "=" * 60) -ForegroundColor Yellow
    Write-Host "MANUAL DOWNLOAD REQUIRED" -ForegroundColor Yellow
    Write-Host ("=" * 60) -ForegroundColor Yellow
    Write-Host "The following $($updatesWithoutUrls.Count) update(s) require manual download:" -ForegroundColor Yellow
    
    foreach ($update in $updatesWithoutUrls) {
      Write-Host "`nKB$($update.KbId): $($update.Title)" -ForegroundColor White
      if ($update.MicrosoftCatalogURL) {
        Write-Host "  Download URL: $($update.MicrosoftCatalogURL)" -ForegroundColor Cyan
      }
      Write-Host "  Alternative: Use Windows Update, WSUS, or manually search Microsoft Update Catalog" -ForegroundColor Gray
    }
    
    Write-Host "`nTip: Visit Microsoft Update Catalog (catalog.update.microsoft.com) for manual downloads" -ForegroundColor Green
    Write-Host ("=" * 60) -ForegroundColor Yellow
  }

  # Display final summary if downloads were requested
  if ($DownloadUpdates) {
    $totalUpdates = $MyUpdates.Count
    $updatesWithUrls = ($MyUpdates | Where-Object { $_.DownloadURL }).Count
    $updatesWithoutUrls = $totalUpdates - $updatesWithUrls
    $successfulDownloads = ($MyUpdates | Where-Object { $_.DownloadSuccess -eq $true }).Count
    
    $summaryTitle = if ($InstallUpdates) { "FINAL DOWNLOAD & INSTALLATION SUMMARY" } else { "FINAL DOWNLOAD SUMMARY" }
    Write-Host ("`n" + "=" * 60) -ForegroundColor Cyan
    Write-Host $summaryTitle -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
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
    Write-Host ("=" * 60) -ForegroundColor Cyan
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

  # Display positive message if no missing updates found
  if ($MyUpdates.Count -eq 0 -and $UpdateSearchFilter -match "IsInstalled=0" -and -not $DownloadUpdates) {
    Write-Host "`nNo missing updates found - system is up to date!" -ForegroundColor Green
  }

  $MyUpdates
}