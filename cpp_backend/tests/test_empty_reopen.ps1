$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe = Join-Path $root '..\build\vault_backend.exe'
$area = Join-Path $root 'test_empty_reopen'
if (Test-Path $area) { Remove-Item -Recurse -Force $area }
New-Item -ItemType Directory -Path $area | Out-Null

$srcDir = Join-Path $area 'src'
New-Item -ItemType Directory -Path $srcDir | Out-Null
$enc = New-Object System.Text.UTF8Encoding($false)
$srcs = @{}
foreach ($spec in @(@('a.txt', 1000, 'A'), @('b.txt', 2000, 'B'), @('c.txt', 3000, 'C'))) {
  $p = Join-Path $srcDir $spec[0]
  [System.IO.File]::WriteAllText($p, ([string]$spec[2] * [int]$spec[1]), $enc)
  $srcs[$spec[0]] = $p
}

$lf = [string][char]10
function Run([string[]]$lines) {
  $payload = ($lines -join $lf) + $lf
  return ($payload | & $exe 2> $null)
}
function Results([string[]]$lines) {
  return (Run $lines | ForEach-Object { $_ | ConvertFrom-Json })
}
function Of($res, [int]$id) {
  return ($res | Where-Object { $_.id -eq $id } | Select-Object -First 1)
}

$v1 = (Join-Path $area 'v1.vault').Replace('\', '/')
$v2 = (Join-Path $area 'v2.vault').Replace('\', '/')
$A = $srcs['a.txt'].Replace('\', '/')
$B = $srcs['b.txt'].Replace('\', '/')
$C = $srcs['c.txt'].Replace('\', '/')
$outA = (Join-Path $area 'out_a.txt').Replace('\', '/')
$outB = (Join-Path $area 'out_b.txt').Replace('\', '/')
$outA2 = (Join-Path $area 'out_a2.txt').Replace('\', '/')

# --- Case 1: delete every file, lock, open again -> must be an empty vault that
#     is still writable, not "corrupt".
$r1 = Results @(
  ('{"id":1,"method":"create","params":{"path":"' + $v1 + '","password":"pw"}}'),
  ('{"id":2,"method":"add","params":{"src":"' + $A + '"}}'),
  ('{"id":3,"method":"add","params":{"src":"' + $B + '"}}'),
  '{"id":4,"method":"delete","params":{"name":"a.txt"}}',
  '{"id":5,"method":"delete","params":{"name":"b.txt"}}',
  '{"id":6,"method":"list"}',
  '{"id":7,"method":"lock"}',
  ('{"id":8,"method":"open","params":{"path":"' + $v1 + '","password":"pw"}}'),
  '{"id":9,"method":"list"}',
  ('{"id":10,"method":"add","params":{"src":"' + $A + '"}}'),
  '{"id":11,"method":"list"}',
  ('{"id":12,"method":"extract_to","params":{"name":"a.txt","dest":"' + $outA + '"}}'),
  '{"id":13,"method":"lock"}',
  ('{"id":14,"method":"open","params":{"path":"' + $v1 + '","password":"pw"}}'),
  '{"id":15,"method":"list"}',
  '{"id":16,"method":"shutdown"}'
)
$open2 = Of $r1 8
$empty = [int](Of $r1 9).result.count
$afterAdd = [int](Of $r1 11).result.count
$final = [int](Of $r1 15).result.count
$bytesA = [System.IO.File]::ReadAllBytes($srcs['a.txt'])
$outAOk = (Test-Path $outA) -and
  ((([System.IO.File]::ReadAllBytes($outA)) -join ',') -eq ($bytesA -join ','))

Write-Output ('case1 reopen ok: ' + $open2.ok)
Write-Output ('case1 list after delete-all: ' + $empty)
Write-Output ('case1 list after re-add: ' + $afterAdd)
Write-Output ('case1 list after second reopen: ' + $final)
Write-Output ('case1 extracted bytes match source: ' + $outAOk)
$pass1 = $open2.ok -and ($empty -eq 0) -and ($afterAdd -eq 1) -and ($final -eq 1) -and $outAOk

# --- Case 2: delete only the trailing file -> the reclaimed tail must not make
#     the next open() look corrupt, and the surviving files must stay intact.
$r2 = Results @(
  ('{"id":1,"method":"create","params":{"path":"' + $v2 + '","password":"pw"}}'),
  ('{"id":2,"method":"add","params":{"src":"' + $A + '"}}'),
  ('{"id":3,"method":"add","params":{"src":"' + $B + '"}}'),
  ('{"id":4,"method":"add","params":{"src":"' + $C + '"}}'),
  '{"id":5,"method":"delete","params":{"name":"c.txt"}}',
  '{"id":6,"method":"lock"}',
  ('{"id":7,"method":"open","params":{"path":"' + $v2 + '","password":"pw"}}'),
  '{"id":8,"method":"list"}',
  ('{"id":9,"method":"extract_to","params":{"name":"a.txt","dest":"' + $outA2 + '"}}'),
  ('{"id":10,"method":"extract_to","params":{"name":"b.txt","dest":"' + $outB + '"}}'),
  '{"id":11,"method":"shutdown"}'
)
$openB = Of $r2 7
$kept = [int](Of $r2 8).result.count
$outA2Ok = (Test-Path $outA2) -and
  ((([System.IO.File]::ReadAllBytes($outA2)) -join ',') -eq ($bytesA -join ','))
$bytesB = [System.IO.File]::ReadAllBytes($srcs['b.txt'])
$outBOk = (Test-Path $outB) -and
  ((([System.IO.File]::ReadAllBytes($outB)) -join ',') -eq ($bytesB -join ','))

Write-Output ('case2 reopen ok: ' + $openB.ok)
Write-Output ('case2 surviving count: ' + $kept)
Write-Output ('case2 a.txt bytes match source: ' + $outA2Ok)
Write-Output ('case2 b.txt bytes match source: ' + $outBOk)
$pass2 = $openB.ok -and ($kept -eq 2) -and $outA2Ok -and $outBOk

$pass = $pass1 -and $pass2
Write-Output ('EMPTY-REOPEN PASS: ' + $pass)
if (-not $pass) { exit 1 }
