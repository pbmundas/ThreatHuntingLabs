$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$pythonCommand = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCommand) { $pythonCommand = Get-Command py -ErrorAction SilentlyContinue }
$codexPython = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
if (-not $pythonCommand -and (Test-Path -LiteralPath $codexPython)) { $pythonCommand = Get-Item -LiteralPath $codexPython }
if (-not $pythonCommand) { throw 'Python is required to start the local lab server.' }
Start-Process -FilePath $pythonCommand.Source -ArgumentList @('-m','http.server','8080','--bind','127.0.0.1') -WorkingDirectory $projectRoot -WindowStyle Hidden
Start-Sleep -Seconds 2
Start-Process 'http://127.0.0.1:8080/'
