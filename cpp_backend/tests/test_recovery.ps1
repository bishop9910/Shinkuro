$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe = Join-Path $root '..\build\vault_backend.exe'
$area = Join-Path $root 'test_recovery'
if (Test-Path $area) { Remove-Item -Recurse -Force $area }
New-Item -ItemType Directory -Path $area | Out-Null

$srcDir = Join-Path $area 'src'
New-Item -ItemType Directory -Path $srcDir | Out-Null
$a = Join-Path $srcDir 'a.txt'; [System.IO.File]::WriteAllText($a, 'AAAA', (New-Object System.Text.UTF8Encoding($false)))
$b = Join-Path $srcDir 'b.txt'; [System.IO.File]::WriteAllText($b, 'BBBB', (New-Object System.Text.UTF8Encoding($false)))

$vault = (Join-Path $area 'v.vault')
$vaultJ = $vault.Replace('\','/')
$lf = [string][char]10

function Run([string[]]$lines) {
  $payload = ($lines -join $lf) + $lf
  $o = $payload | & $exe 2> $null
  return $o
}

# 1) create + add two files, then lock.
$out = Run @(
  ('{"id":1,"method":"create","params":{"path":"' + $vaultJ + '","password":"pw"}}'),
  ('{"id":2,"method":"add","params":{"src":"' + $a.Replace('\','/') + '"}}'),
  ('{"id":3,"method":"add","params":{"src":"' + $b.Replace('\','/') + '"}}'),
  '{"id":4,"method":"lock"}',
  '{"id":5,"method":"shutdown"}'
)
$out | Out-Null

# 2) Simulate a torn compact: backup the vault, then bump the live vault's
#    generation to 2 while the index remains at generation 1.
$vaultOld = $vault + '.old'
Copy-Item $vault $vaultOld
$bytes = [System.IO.File]::ReadAllBytes($vault)
# generation lives at offset 64..71 (little-endian u64)
for ($i = 0; $i -lt 8; $i++) { $bytes[64 + $i] = 0 }
$bytes[64] = 2
[System.IO.File]::WriteAllBytes($vault, $bytes)

# 3) Reopen: recovery should detect the generation mismatch, roll back the .old
#    backup, and open cleanly with both files present.
$out2 = Run @(
  ('{"id":1,"method":"open","params":{"path":"' + $vaultJ + '","password":"pw"}}'),
  '{"id":2,"method":"list"}',
  '{"id":3,"method":"shutdown"}'
)
$parsed = $out2 | ForEach-Object { $_ | ConvertFrom-Json }
$listRes = ($parsed | Where-Object { $_.result -and $_.result.count -ne $null } | Select-Object -First 1)
$count = [int]$listRes.result.count
$vaultOldGone = -not (Test-Path $vaultOld)

Write-Output ('recovered list count: ' + $count)
Write-Output ('vault.old cleaned up: ' + $vaultOldGone)
$pass = ($count -eq 2) -and $vaultOldGone
Write-Output ('RECOVERY PASS: ' + $pass)
if (-not $pass) { exit 1 }
