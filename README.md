# loghawk

> **One Perl script, zero dependencies: parse, filter, chart and anomaly-hunt
> any server log from the command line.**

![Language](https://img.shields.io/badge/language-Perl%205-blueviolet)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-core%20only-brightgreen)
![Tests](https://img.shields.io/badge/tests-441%20passing-success)
![Platform](https://img.shields.io/badge/platform-POSIX-lightgrey)

---

## Overview

`loghawk` reads one or more log files (or STDIN), normalizes the mixed formats
real servers actually produce - Apache/nginx combined and common access logs,
Apache error logs, BSD syslog, ISO/RFC 5424-style syslog and JSON lines - into
a single record stream, and then answers operational questions:

- *What happened?* - `parse`, `filter`, `export`
- *How much, and when?* - `stats`, `series`
- *Is what is happening right now normal?* - `spikes`, `tailf`
- *What do I send to the team?* - `report` (text / markdown / HTML)

It is intentionally dependency-free: a plain Perl 5 (>= 5.14) install with
only core modules is enough. No CPAN client, no build step, no container.

```
$ loghawk spikes --unit hour examples/sample_access.log
BUCKET                    VALUE       MEAN        Z DIR    SEVERITY
2025-11-17 10:00             27      17.30     3.10 up     low
2025-11-18 14:00            121      19.57    27.75 up     critical

Incidents:
  - 2025-11-17 10:00  1 bucket(s), peak 27 (z=3.10, low)
  - 2025-11-18 14:00  1 bucket(s), peak 121 (z=27.75, critical)
risk score: 27.75
```

## Features

| Area | What you get |
|---|---|
| Parsing | Per-line format detection; combined/common/error/syslog/JSON mixed freely in one stream; tolerant of garbage (counted, never fatal) |
| Filtering | Status classes & codes, IP (exact / CIDR / glob / regex), URL substring & regex, method, syslog level, time windows (`--since`/`--until`), byte range, raw-line grep |
| Aggregation | Status distribution, top IPs/URLs/referers, bandwidth by day, peak minute/hour, browser/OS/device classification from User-Agent strings |
| Latency | Global duration percentiles (p50/p95/p99), per-path latency profiles, top-10 slowest requests |
| Time series | second/minute/hour/day (or arbitrary N-second) buckets with gap filling, sparklines and ASCII bar charts |
| Anomalies | Rolling z-score spike/dip detection with severity grades, incident merging, and an EWMA baseline for trending traffic |
| Live mode | `tailf` follows growing files with inode-rotation and truncation tolerance plus per-minute spike alerting |
| Reports | 78-column text, GitHub-flavoured markdown and standalone HTML (embedded CSS, zero external assets) |
| Export | JSON, NDJSON (jq-friendly) and RFC 4180 CSV with column selection |

## Requirements

- Perl 5.14 or newer (tested on Perl 5.40) - any modern Linux/BSD/macOS has it
- Core modules only: `Getopt::Long`, `Pod::Usage`, `POSIX`, `Exporter`,
  `File::Temp` (tests), `Time::Piece`, `Time::HiRes`, `JSON::PP`
- `prove` (ships with Perl) for the test suite - optional
- `make` - optional, convenience targets only

There is nothing to install besides cloning or copying the directory.

## Installation

```bash
git clone https://github.com/buifkhanh57-hub/loghawk.git
cd loghawk
perl -c bin/loghawk          # verify it compiles
perl bin/loghawk --help      # say hello
```

For everyday use, drop it on your `PATH`:

```bash
sudo install -m 0755 bin/loghawk /usr/local/bin/loghawk
# or, without root:
ln -s "$PWD/bin/loghawk" ~/.local/bin/loghawk
```

`bin/loghawk` locates its libraries relative to its own path
(`FindBin`), so a symlink works fine.

## Quick Start

```bash
# overview of an access log: statuses, top talkers, bandwidth, peak minute
loghawk stats examples/sample_access.log

# every 5xx of the last hour as CSV
loghawk filter --status 5xx --since -1h --csv access.log > out.csv

# requests per hour as an ASCII chart
loghawk series --unit hour --chart examples/sample_access.log

# flag anomalous traffic
loghawk spikes --sensitivity high examples/sample_access.log

# live follow with spike alerts
tail -F /var/log/nginx/access.log | loghawk tailf -
```

## Usage

`loghawk COMMAND [options] [file...]` - files may be mixed freely and `-`
means STDIN; with no file, STDIN is read.

| Command | Purpose | Highlights |
|---|---|---|
| `parse` | Normalize any supported format into records | `--json`, `--csv`, `--limit N`, `--diag`, `--no-raw` |
| `stats` | Aggregated overview (top IPs/URLs, statuses, UA, latency) | `--top N`, `--json`, `--diag` |
| `filter` | Surgical record extraction | `--status`, `--ip`, `--url`, `--url-regex`, `--method`, `--level`, `--since/--until`, `--min-bytes/--max-bytes`, `--grep`, output: `--json/--csv/--raw`, `--count`, `--limit N` |
| `series` | Time bucketing and charts | `--unit second\|minute\|hour\|day\|N`, `--value count\|bytes\|errors`, `--chart`, `--no-fill`, `--json` |
| `spikes` | z-score anomaly detection | `--unit`, `--value`, `--window N`, `--sensitivity low\|medium\|high`, `--threshold F`, `--mode spikes\|dips\|both`, `--baseline rolling\|ewma`, `--alpha F`, `--json` |
| `tailf` | Follow a growing log with alerts | `--from-start`, `--interval F`, `--max-runtime S`, `--max-lines N`, `--alert-threshold F`, `--sensitivity S`, `--no-alert`, `--quiet` |
| `report` | text / markdown / HTML document | `--format`, `--output FILE`, `--title`, `--top N`, `--unit`, `--no-series`, `--no-spikes`, plus all filter options |
| `export` | Dump records as JSON/NDJSON/CSV | `--format json\|ndjson\|csv`, `--output FILE`, `--compact`, `--fields a,b,c`, plus all filter options |

Every filter option understood by `filter` is also accepted by `series`,
`spikes`, `report` and `export`, so "the same slice, but aggregated" is one
flag away.

### Real output samples

All samples below were captured with `bin/loghawk` against
`examples/sample_access.log` (1,000 requests over 48 h with an injected
brute-force window; see [Project Structure](#project-structure)).

**`loghawk parse examples/sample_access.log | head -4`**

```
TIME                TYPE     STAT METHOD URL/MESSAGE                        IP              BYTES
2025-11-17T00:00:30 combined 200  GET    /products                          203.0.113.7     24,701
2025-11-17T00:02:48 combined 200  GET    /health                            203.0.113.88        6
2025-11-17T00:02:56 combined 404  GET    /                                  10.0.0.5        3,200
```

**`loghawk stats --top 3 examples/sample_access.log` (excerpt)**

```
STATUS CODES
------------
  CLASS  COUNT  SHARE
  -----  -----  -----
  2xx      621  62.1%
  3xx       85   8.5%
  4xx      198  19.8%
  5xx       96   9.6%

TOP CLIENT IPS
--------------
  #  IP             REQS     BYTES  LOAD
  -  -------------  ----  --------  ------------------------
  1  198.51.100.73    79  576.0 KB  ########################
  2  198.51.100.72    78  568.8 KB  ########################
  3  198.51.100.71    74  341.6 KB  ######################

LATENCY BY PATH (MS)
--------------------
  PATH               TIMED     AVG     P50     P95     MAX
  -----------------  -----  ------  ------  ------  ------
  /api/v1/orders/42     44  130670   99329  451209  533823
  /api/v1/users         79  124344   90495  426979  490341

Slowest requests:
  632854 ms  /api/v1/orders                      10.0.0.6
  607166 ms  /dashboard                          192.0.2.57
```

**`loghawk filter --status 5xx --count examples/sample_access.log`**

```
96
```

**`loghawk series --unit hour examples/sample_access.log` (excerpt)**

```
BUCKET                      VALUE   REQUESTS      BYTES     ERRORS
2025-11-17 00:00               21         21   125.4 KB         10
2025-11-17 01:00               19         19   246.1 KB          4
2025-11-17 02:00               14         14   128.8 KB          3
```

**`loghawk spikes --unit hour examples/sample_access.log`** - see
[Overview](#overview); the injected 14:00 hour (121 requests vs a mean of
~20) is flagged `critical` with z = 27.75.

**`loghawk export --format json examples/sample_access.log` (excerpt)**

```json
{
   "meta" : { "count" : 1000, "format" : "loghawk-records/1" },
   "records" : [
      {
         "bytes" : 24701,
         "duration_ms" : 13822,
         "ip" : "203.0.113.7",
         "method" : "GET",
         "path" : "/products",
         "status" : 200,
         "ts_iso" : "2025-11-17T00:00:30Z",
         "type" : "combined"
      }
   ]
}
```

## Supported log formats

Detection happens per line, so a single stream may mix formats.

| Format | Example line |
|---|---|
| Apache/nginx combined | `1.2.3.4 - alice [18/Nov/2025:03:07:12 +0000] "GET / HTTP/1.1" 200 512 "http://ref" "UA/1.0"` |
| Apache/nginx common | same, without referer/UA (an optional trailing `%D` microsecond field is captured as `duration_ms`) |
| Apache error log | `[Tue Nov 18 03:10:00 2025] [error] [client 198.51.100.7] File does not exist: ...` |
| BSD syslog (RFC 3164) | `<34>Nov 18 03:11:22 web01 sshd[2318]: Failed password ...` (PRI optional) |
| ISO / RFC 5424-style syslog | `2025-11-18T03:15:00.123Z web01 nginx: upstream timed out ...` |
| JSON lines | `{"@timestamp":"...","remote_addr":"...","status_code":504,"msg":"..."}` - common key aliases auto-mapped, unknown keys preserved under `data` |

Unparsable lines never abort a run: they are counted in
`stats->{skipped}` and the first 20 samples are kept for `parse --diag`.
Malformed CLF timestamps still produce a record (with `ts` undef).

`--since` / `--until` accept `now`, relative offsets (`-30s -5m -2h -1d -1w`),
dates (`2025-11-18`), ISO 8601 datetimes with optional zone, Apache CLF
timestamps and bare `HH:MM[:SS]`.

## Anomaly detection explained

`loghawk spikes` buckets the (optionally filtered) records into a dense time
series and scores every bucket against the traffic before it:

1. **Baseline.** Two interchangeable methods:
   - *rolling* (default): the previous `--window` buckets (default 30) give a
     plain mean and standard deviation. Transparent - every alert can be
     recomputed by hand from the printed baseline.
   - *ewma*: an exponentially weighted moving average (`--alpha`, default
     0.3) tracks trending traffic instead of one flat window:

     ```
     d   = v - mu          # deviation of the bucket
     mu  = mu + alpha * d  # smoothed level
     var = (1-alpha)*var + alpha*d*d   # smoothed variance
     ```

     Small `alpha` remembers long history; large `alpha` follows the traffic
     and only sudden jumps trip. In both cases the current bucket never
     contributes to its own baseline.
2. **Score.** `z = (value - baseline_mean) / max(baseline_sd, 1)` - the
   epsilon keeps flat baselines sane: any deviation from a perfectly constant
   period is caught, but a constant series never false-alarms.
3. **Flag.** A bucket is flagged when `z >= threshold` (spikes), `z <= -threshold`
   (dips) or either (`--mode both`). `--sensitivity low|medium|high` maps to
   thresholds 4.0 / 3.0 / 2.0; `--threshold` overrides.
4. **Severity.** From |z|: >= 6 critical, >= 4.5 high, >= 3.5 medium, else low.
5. **Incidents.** Consecutive flagged buckets merge into one event, so a
   sustained burst reads as one alert, not fifty.

The whole run also prints a single **risk score** (max |z| seen) - handy as a
CI gate: `loghawk spikes --sensitivity low access.log` and alert when the
number is non-zero. On sparse data (a quiet log where most minutes are empty)
per-minute scores are naturally twitchy; aggregate first (`--unit hour` or
`--unit 600`) and the signal is unmistakable.

`loghawk tailf` runs the same detector live: completed minutes feed the
baseline and `on_spike` alerts are printed to STDERR.

## Project Structure

```
loghawk/
|-- Makefile                      make compile | test | smoke | smoke-report | clean
|-- README.md                     this file
|-- bin/
|   `-- loghawk                   CLI entry point: dispatch, option parsing, embedded POD (--man)
|-- examples/
|   `-- sample_access.log         1,000-line combined-format sample (48 h, 20 IPs, 15 paths,
|                                 weighted 200/301/404/500, 6 UAs, injected 10-minute
|                                 brute-force spike from 3 IPs at 2025-11-18 14:20 UTC);
|                                 regenerate with scripts/gen_sample_log.py (seeded, reproducible)
|-- lib/
|   |-- LogHawk.pm                version holder + command registry used by the help screen
|   `-- LogHawk/
|       |-- Anomaly.pm            rolling & EWMA z-score detection, severity, incident merging
|       |-- Export.pm             JSON / NDJSON / CSV serialization (RFC 4180, canonical JSON)
|       |-- Filters.pm            composable record predicates (status/ip/url/time/level/bytes)
|       |-- Parser.pm             combined/common/error/syslog/JSON-line parsing + counters
|       |-- Report.pm             text / markdown / HTML renderers
|       |-- Series.pm             time bucketing, gap filling, sparkline & ASCII charts
|       |-- Stats.pm              aggregations, UA intelligence, latency percentiles
|       |-- Tail.pm               follow mode, rotation/truncation tolerance, live alerts
|       `-- Util.pm               sizes, numbers, UTC calendar math, small statistics
`-- t/
    |-- anomaly.t                 detector behaviour incl. EWMA (70 checks)
    |-- export.t                  CSV/JSON serialization + Filters (67 checks)
    |-- parser.t                  parser + time arithmetic (128 checks)
    |-- series.t                  bucketing, charts, resample (47 checks)
    `-- stats.t                   aggregation, UA matrix, latency (129 checks)
```

The sample log is generated by `/home/z/my-project/scripts/gen_sample_log.py`
in the workspace checkout - a small deterministic Python script (fixed seed),
so `examples/sample_access.log` can always be regenerated byte-identically.

## Architecture

```
                files / STDIN
                     |
               LogHawk::Parser      per-line format detection -> record hashrefs
                     |
               LogHawk::Filters     predicate closures (AND chain, fail-closed on time)
                     |
      +--------------+---------------+----------------+
      |              |               |                |
LogHawk::Stats  LogHawk::Series  LogHawk::Export  LogHawk::Tail
 (aggregates,    (buckets, gap    (JSON/NDJSON/    (follow mode,
  UA, latency)    fill, charts)    CSV writers)     live alerting)
      |              |
      |         LogHawk::Anomaly   rolling / EWMA z-scores, events, risk
      |              |
      +------+-------+
             |
       LogHawk::Report        text / markdown / HTML rendering
             |
          bin/loghawk        Getopt::Long dispatch, exit codes 0/1/2
```

Design rules that hold across the codebase:

- **Plain data everywhere.** Modules exchange unblessed hashrefs; any stage
  can be driven from a script, not only from the CLI.
- **UTC-only time math.** Epochs are computed with the days-from-civil
  algorithm, so output never depends on the host timezone; formatting uses
  `gmtime`.
- **Tolerance, then accounting.** Bad input is skipped, counted and sampled -
  never fatal, never silent.
- **Bounded memory.** Top-N lists use insertion buffers, per-path latency
  samples slide (512 newest), the tailer keeps a 240-minute history window.
- **Stable output.** JSON is emitted with canonical key ordering, so two runs
  over the same log produce byte-identical artifacts.

## Testing

```bash
make test            # prove -Ilib t/*.t
make verbose         # full TAP output
prove -r t/          # directly
perl t/parser.t      # one file at a time
```

Current suite: **5 files, 441 assertions, all passing** (Perl 5.40).

| File | Covers |
|---|---|
| `t/parser.t` | time grammar (CLF/ISO/syslog/relative), combined/common/error/syslog/JSON records, tolerance counters, file handles |
| `t/stats.t` | 15-case UA classification matrix, aggregation, top-N ordering/ties, duration percentiles, latency profiles & slowest list |
| `t/series.t` | unit validation, gap filling, value modes, sparklines, charts, resample |
| `t/anomaly.t` | thresholds/sensitivity, dips, event merging, min-history gate, EWMA method incl. alpha validation |
| `t/export.t` | CSV escaping, JSON/NDJSON shapes, series CSV, write_file, all filter predicates incl. CIDR |

`make smoke` / `make smoke-report` run every subcommand against the sample log
as an end-to-end check; `make compile` syntax-checks the binary and all
modules.

## FAQ

**Why Perl in 2025?**
Because it is already on every server you SSH into, boots instantly, and its
regex engine is ideal for log surgery. loghawk targets "zero install"
operations work, not language fashion.

**Can it handle multi-GB logs?**
Yes - parsing is streaming (`parse_file` feeds a callback line by line) and
the aggregators use bounded buffers. Only `filter`/`export` materialize the
matched records, which you usually slice with `--limit` anyway.

**The `spikes` output on my quiet log is noisy. Is that broken?**
No - with mostly-empty minute buckets, any minute with 2-3 requests has a
high z-score. Aggregate first (`--unit hour` or `--unit 600`) or raise
`--sensitivity low`. Sparse data is exactly the case the EWMA baseline with a
small `--alpha` was added for.

**Windows logs (IIS/EVTX)?**
Not yet; see the roadmap. If you can convert to combined format or JSON
lines, loghawk will happily analyze them today.

**IPv6?**
Parsing keeps IPv6 hosts as strings, and exact/regex `--ip` filters work;
CIDR matching is IPv4-only for now.

**Does it send anything anywhere?**
No. No network calls, no telemetry, no plugins. It reads files and writes
STDOUT.

**How do I contribute?**
Fork, add a failing test in `t/`, make it pass, keep the POD honest, and send
a pull request. `make test` must stay green.

## Roadmap

- GeoIP enrichment for the top-IP table (offline mmdb reader, opt-in)
- Response-time percentiles per status class, not only per path
- IPv6 CIDR matching in `LogHawk::Filters`
- `logwatch`-style daily diff: `loghawk report --compare yesterday.log`
- IIS/W3C extended format parser
- Optional YAML export for Ansible-style inventories
- Daemon mode with alert webhooks for `tailf`

## License

MIT License

Copyright (c) 2025 Bui Bao Khanh

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

---
**by Bui Bao Khanh**
