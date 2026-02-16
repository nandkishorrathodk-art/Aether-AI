$path = "C:\Users\nandk\OneDrive\Desktop\Vy.lnk"
try {
    $sh = New-Object -ComObject WScript.Shell
    if (Test-Path $path) {
        $lnk = $sh.CreateShortcut($path)
        Write-Output "TARGET_PATH: $($lnk.TargetPath)"
    } else {
        Write-Error "Shortcut file not found at: $path"
    }
} catch {
    Write-Error "Failed to resolve shortcut: $_"
}
