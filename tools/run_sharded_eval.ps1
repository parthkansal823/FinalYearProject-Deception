# Shard a multi-seed evaluation across N concurrent processes.
#
# The evaluation is I/O-bound, not compute-bound: nearly all of its wall clock is
# sequential HTTP round-trips and generator think-times, and the only learned
# component is two logistic regressions costing microseconds per request. So it
# does not benefit from a GPU at all -- but it shards almost linearly across
# processes, because each shard owns a disjoint set of traffic seeds.
#
# Every path and port a run touches is config-driven, so a shard is isolated by
# ADF_* environment overrides plus --out-dir. Nothing is shared but the frozen
# model, the cost table and the bait library, all of which are read-only.
#
#   ./tools/run_sharded_eval.ps1 -Shards 4 -Seeds 100 -Tag curious
#
# Merge the shards afterwards with tools/merge_shards.py, then run stats_report.

param(
    [int]    $Shards    = 4,
    [int]    $Seeds     = 100,
    [int]    $BaseSeed  = 20260913,
    [int]    $Attack    = 120,
    [int]    $Benign    = 80,
    [string] $Arms      = "b1_rules,b2_passive,b4_full",
    [string] $Tag       = "sharded",
    [int]    $PortBase  = 9000
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

$per = [math]::Floor($Seeds / $Shards)
$rem = $Seeds % $Shards
if ($per -lt 1) { throw "need at least one seed per shard (Seeds=$Seeds, Shards=$Shards)" }

$root = "data/eval/$Tag"
New-Item -ItemType Directory -Force -Path $root | Out-Null

Write-Host "sharding $Seeds seeds over $Shards processes -> $root" -ForegroundColor Cyan

$offset = 0
$jobs = @()
for ($i = 0; $i -lt $Shards; $i++) {
    # spread the remainder over the first shards so no seed is dropped
    $n = $per; if ($i -lt $rem) { $n = $per + 1 }
    $seed0 = $BaseSeed + $offset
    $offset += $n

    # each shard gets its own port triple; 3 ports apart so they cannot collide
    $p = $PortBase + ($i * 3)
    $dir = "$root/shard$i"

    Write-Host ("  shard {0}: seeds {1}..{2} ({3} draws)  ports {4}/{5}/{6}  -> {7}" -f `
        $i, $seed0, ($seed0 + $n - 1), $n, $p, ($p + 1), ($p + 2), $dir)

    $env:ADF_NETWORK__PROXY_PORT   = "$p"
    $env:ADF_NETWORK__TARGET_PORT  = "$($p + 1)"
    $env:ADF_NETWORK__DECOY_PORT   = "$($p + 2)"
    $env:ADF_LOGGING__LOG_DIR      = "$dir/logs"
    $env:ADF_LOGGING__LABEL_DIR    = "$dir/labels"
    $env:ADF_DATABASES__TARGET_DSN = "sqlite:///$dir/target.sqlite3"
    $env:ADF_DATABASES__FACT_NOTEBOOK_DSN = "sqlite:///$dir/notebook.sqlite3"

    $jobs += Start-Process -FilePath "python" -PassThru -NoNewWindow `
        -RedirectStandardOutput "$root/shard$i.log" `
        -RedirectStandardError  "$root/shard$i.err" `
        -ArgumentList @("-m", "tools.multiseed_eval",
                        "--seeds", "$n", "--base-seed", "$seed0",
                        "--attack", "$Attack", "--benign", "$Benign",
                        "--arms", $Arms, "--out-dir", $dir)
}

Write-Host ""
Write-Host "$($jobs.Count) shards running. PIDs: $($jobs.Id -join ', ')" -ForegroundColor Green
Write-Host "follow with:  Get-Content $root/shard0.log -Wait -Tail 5"
Write-Host "when all exit: python -m tools.merge_shards --tag $Tag ; python -m tools.stats_report --in data/eval/$Tag/sessions.jsonl"
