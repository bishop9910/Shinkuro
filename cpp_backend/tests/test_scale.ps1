$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe = Join-Path $root '..\build\vault_backend.exe'
$area = Join-Path $root 'test_scale'
if (Test-Path $area) { Remove-Item -Recurse -Force $area }
New-Item -ItemType Directory -Path $area | Out-Null

$N = 400
# create source files
$srcDir = Join-Path $area 'src'
New-Item -ItemType Directory -Path $srcDir | Out-Null
$contentMap = @{}
for ($i = 0; $i -lt $N; $i++) {
  $name = ('f{0:d4}.txt' -f $i)
  $p = Join-Path $srcDir $name
  $c = ('content-of-' + $i + '-padding-' + ('x' * (($i % 97) + 1)))
  [System.IO.File]::WriteAllText($p, $c, (New-Object System.Text.UTF8Encoding($false)))
  $contentMap[$name] = $c
}

$vault = (Join-Path $area 'v.vault').Replace('\','/')
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('{"id":1,"method":"create","params":{"path":"' + $vault + '","password":"pw"}}')
$id = 2
for ($i = 0; $i -lt $N; $i++) {
  $name = ('f{0:d4}.txt' -f $i)
  $lines.Add('{"id":' + $id + ',"method":"add","params":{"src":"' + (Join-Path $srcDir $name).Replace('\','/') + '"}}')
  $id++
}
$lines.Add('{"id":' + $id + ',"method":"list"}'); $id++
# delete first half
for ($i = 0; $i -lt ($N/2); $i++) {
  $name = ('f{0:d4}.txt' -f $i)
  $lines.Add('{"id":' + $id + ',"method":"delete","params":{"name":"' + $name + '"}}')
  $id++
}
$lines.Add('{"id":' + $id + ',"method":"list"}'); $id++
$lines.Add('{"id":' + $id + ',"method":"compact"}'); $id++
$lines.Add('{"id":' + $id + ',"method":"lock"}'); $id++
$lines.Add('{"id":' + $id + ',"method":"open","params":{"path":"' + $vault + '","password":"pw"}}'); $id++
$lines.Add('{"id":' + $id + ',"method":"list"}'); $id++
$lines.Add('{"id":' + $id + ',"method":"shutdown"}')

$lf = [string][char]10
$payload = ($lines -join $lf) + $lf
$output = $payload | & $exe 2> (Join-Path $area 'err.txt')
$output | Out-File (Join-Path $area 'resp.txt') -Encoding UTF8

# Parse the two list responses (before delete-half list, after delete-half list, after reopen list)
$all = $output | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.ok -and $_.result }
$lists = $all | Where-Object { $_.result.count -ne $null }
Write-Output ('list responses found: ' + $lists.Count)
foreach ($l in $lists) { Write-Output ('  count=' + $l.result.count + ' free=' + $l.result.free_bytes + ' physical=' + $l.result.physical_size) }

$expectedCounts = @($N, ($N/2), ($N/2))
$pass = ($lists.Count -eq 3)
if ($pass) {
  for ($k = 0; $k -lt 3; $k++) {
    if ([int]$lists[$k].result.count -ne [int]$expectedCounts[$k]) { $pass = $false }
  }
}
# verify a few surviving files by extracting after reopen
$surv = ('f{0:d4}.txt' -f 300)
$outP = (Join-Path $area 'out.txt').Replace('\','/')
$exLines = New-Object System.Collections.Generic.List[string]
$exLines.Add('{"id":1,"method":"open","params":{"path":"' + $vault + '","password":"pw"}}')
$exLines.Add('{"id":2,"method":"extract_to","params":{"name":"' + $surv + '","dest":"' + $outP + '"}}')
$exLines.Add('{"id":3,"method":"shutdown"}')
$exPayload = ($exLines -join $lf) + $lf
$exOut = $exPayload | & $exe 2> $null
$exBytes = $null
if (Test-Path (Join-Path $area 'out.txt')) { $exBytes = [System.IO.File]::ReadAllBytes((Join-Path $area 'out.txt')) }
$expectBytes = [System.IO.File]::ReadAllBytes((Join-Path $srcDir $surv))
$extractOk = ($exBytes -ne $null) -and (($exBytes -join ',') -eq ($expectBytes -join ','))
Write-Output ('extract surviving file matches: ' + $extractOk)

Write-Output ('SCALE PASS: ' + ($pass -and $extractOk))
if (-not ($pass -and $extractOk)) { exit 1 }
