# Test script to debug WSUS offline scan issues
param(
    [string]$WSUSScanFile = ".\wsusscn2.cab",
    [string]$UpdateSearchFilter = "IsInstalled=0"
)

Write-Host "Starting WSUS offline scan debug test..." -ForegroundColor Cyan
Write-Host "Scan file: $WSUSScanFile" -ForegroundColor White
Write-Host "Filter: $UpdateSearchFilter" -ForegroundColor White

# Check if file exists
if (-not (Test-Path $WSUSScanFile)) {
    Write-Error "WSUS scan file not found: $WSUSScanFile"
    exit 1
}

# Resolve to absolute path
$scanFile = Resolve-Path $WSUSScanFile | Select-Object -ExpandProperty Path
Write-Host "Resolved path: $scanFile" -ForegroundColor Green

# Get file size for verification
$fileInfo = Get-Item $scanFile
Write-Host "File size: $([math]::Round($fileInfo.Length / 1MB, 2)) MB" -ForegroundColor Green

try {
    Write-Host "`nCreating COM objects..." -ForegroundColor Yellow
    
    # Create update session and searcher for offline scan
    $session = New-Object -ComObject Microsoft.Update.Session
    Write-Host "Created Update Session" -ForegroundColor Green
    
    $searcher = $session.CreateUpdateSearcher()
    Write-Host "Created Update Searcher" -ForegroundColor Green
    
    # Set up offline scanning using the .cab file
    $searcher.Online = $false
    $searcher.SearchScope = 1  # MachineOnly
    Write-Host "Set searcher to offline mode" -ForegroundColor Green
    
    # For offline scanning, we need to set the server selection to use the local .cab file
    $updateServiceManager = New-Object -ComObject Microsoft.Update.ServiceManager
    Write-Host "Created Service Manager" -ForegroundColor Green
    
    Write-Host "Adding scan package service..." -ForegroundColor Yellow
    $updateService = $updateServiceManager.AddScanPackageService("Offline Sync Service", $scanFile, 1)
    Write-Host "Service ID: $($updateService.ServiceID)" -ForegroundColor Green
    
    $searcher.ServerSelection = 3  # ssOthers
    $searcher.ServiceID = $updateService.ServiceID
    Write-Host "Configured searcher with Service ID" -ForegroundColor Green
    
    # Test different search filters
    $testFilters = @(
        "IsInstalled=0",
        "IsInstalled=1", 
        "IsHidden=0",
        "IsInstalled=0 and IsHidden=0",
        "IsInstalled=1 and IsHidden=0"
    )
    
    foreach ($filter in $testFilters) {
        Write-Host "`nTesting filter: $filter" -ForegroundColor Cyan
        try {
            $results = $searcher.Search($filter)
            Write-Host "  Found $($results.Updates.Count) updates" -ForegroundColor White
            
            if ($results.Updates.Count -gt 0) {
                Write-Host "  First few updates:" -ForegroundColor Gray
                for ($i = 0; $i -lt [Math]::Min(3, $results.Updates.Count); $i++) {
                    $update = $results.Updates[$i]
                    Write-Host "    - KB$($update.KBArticleIDs[0]): $($update.Title)" -ForegroundColor Gray
                    Write-Host "      Installed: $($update.IsInstalled), Hidden: $($update.IsHidden)" -ForegroundColor Gray
                }
            }
        }
        catch {
            Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    # Clean up the temporary service
    Write-Host "`nCleaning up..." -ForegroundColor Yellow
    $updateServiceManager.RemoveService($updateService.ServiceID)
    Write-Host "Service removed successfully" -ForegroundColor Green
    
}
catch {
    Write-Error "Error during offline scan setup: $($_.Exception.Message)"
    Write-Host "Full error details:" -ForegroundColor Red
    Write-Host $_.Exception.ToString() -ForegroundColor Red
    exit 1
}

Write-Host "`nDebug test completed!" -ForegroundColor Cyan