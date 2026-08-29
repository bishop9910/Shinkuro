$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path   # cpp_backend\build
$exe = Join-Path $root '..\build\vault_backend.exe'
$area = Join-Path $root 'test_vault'
if (Test-Path $area) { Remove-Item -Recurse -Force $area }
New-Item -ItemType Directory -Path $area | Out-Null

$src = Join-Path $area 'hello.txt'
$content = "Hello, Shinkuro B+tree!`r`nline2`r`n"
[System.IO.File]::WriteAllText($src, $content, (New-Object System.Text.UTF8Encoding($false)))

$vault = (Join-Path $area 'v.vault').Replace('\','/')
$srcJ  = $src.Replace('\','/')
$out1  = (Join-Path $area 'out1.txt').Replace('\','/')
$out2  = (Join-Path $area 'out2.txt').Replace('\','/')

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('{"id":1,"method":"create","params":{"path":"' + $vault + '","password":"pw1"}}')
$lines.Add('{"id":2,"method":"add","params":{"src":"' + $srcJ + '"}}')
$lines.Add('{"id":3,"method":"list"}')
$lines.Add('{"id":4,"method":"extract_to","params":{"name":"hello.txt","dest":"' + $out1 + '"}}')
$lines.Add('{"id":5,"method":"delete","params":{"name":"hello.txt"}}')
$lines.Add('{"id":6,"method":"add","params":{"src":"' + $srcJ + '"}}')
$lines.Add('{"id":7,"method":"compact"}')
$lines.Add('{"id":8,"method":"change_password","params":{"old_password":"pw1","new_password":"pw2"}}')
$lines.Add('{"id":9,"method":"list"}')
$lines.Add('{"id":10,"method":"lock"}')
$lines.Add('{"id":11,"method":"open","params":{"path":"' + $vault + '","password":"pw2"}}')
$lines.Add('{"id":12,"method":"list"}')
$lines.Add('{"id":13,"method":"extract_to","params":{"name":"hello.txt","dest":"' + $out2 + '"}}')
$lines.Add('{"id":14,"method":"shutdown"}')

$outFile = Join-Path $area 'resp.txt'
$errFile = Join-Path $area 'err.txt'
$lf = [string][char]10
$payload = ($lines -join $lf) + $lf
$output = $payload | & $exe 2> $errFile
$output | Out-File $outFile -Encoding UTF8

Write-Output '===== RESPONSES ====='
Get-Content $outFile -Encoding UTF8
Write-Output '===== STDERR ====='
Get-Content $errFile -Encoding UTF8 -ErrorAction SilentlyContinue

Write-Output '===== VERIFY ====='
$srcBytes  = [System.IO.File]::ReadAllBytes($src)
$ok1 = $false; $ok2 = $false
if (Test-Path $out1) { $ok1 = ([System.IO.File]::ReadAllBytes((Join-Path $area 'out1.txt')) -join ',') -eq ($srcBytes -join ',') }
if (Test-Path $out2) { $ok2 = ([System.IO.File]::ReadAllBytes((Join-Path $area 'out2.txt')) -join ',') -eq ($srcBytes -join ',') }
Write-Output ("extract_to (old pw) matches source: " + $ok1)
Write-Output ("extract_to (new pw) matches source: " + $ok2)
Write-Output ("idx v2 file exists: " + (Test-Path (Join-Path $area 'v.vault.idx')))
if (-not ($ok1 -and $ok2)) { exit 1 }
