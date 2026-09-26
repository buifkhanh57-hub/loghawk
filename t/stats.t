#!/usr/bin/env perl
# t/stats.t - LogHawk::Stats aggregations and UA classification tests
use strict;
use warnings;

use Test::More;
use FindBin;
use lib "$FindBin::Bin/../lib";

use LogHawk::Stats;
use LogHawk::Parser;
use LogHawk::Util qw(ymd_epoch);

# ---------------------------------------------------------------------------
# UA classification matrix
# ---------------------------------------------------------------------------

my @ua_cases = (
    [ 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Chrome', 'Windows', 'Desktop', 'browser' ],
    [ 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0',
      'Edge', 'macOS', 'Desktop', 'browser' ],
    [ 'Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0',
      'Firefox', 'Linux', 'Desktop', 'browser' ],
    [ 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1',
      'Safari', 'iOS', 'Mobile', 'browser' ],
    [ 'Mozilla/5.0 (iPad; CPU OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1',
      'Safari', 'iOS', 'Tablet', 'browser' ],
    [ 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36',
      'Chrome', 'Android', 'Mobile', 'browser' ],
    [ 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
      'Googlebot', 'Unknown', 'Bot', 'bot' ],
    [ 'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
      'YandexBot', 'Unknown', 'Bot', 'bot' ],
    [ 'curl/8.4.0', 'curl', 'Other', 'Other', 'tool' ],
    [ 'Wget/1.21.2 (linux-gnu)', 'Wget', 'Linux', 'Other', 'tool' ],
    [ 'python-requests/2.31.0', 'python-requests', 'Other', 'Other', 'tool' ],
    [ 'Go-http-client/2.0', 'Go HTTP Client', 'Other', 'Other', 'tool' ],
    [ 'Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko',
      'Internet Explorer', 'Windows', 'Desktop', 'browser' ],
    [ 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0',
      'Opera', 'Windows', 'Desktop', 'browser' ],
    [ '', 'Unknown', 'Unknown', 'Other', 'browser' ],
);

for my $case (@ua_cases) {
    my ($ua, $browser, $os, $device, $kind) = @$case;
    my $info = LogHawk::Stats::parse_ua($ua);
    is($info->{browser}, $browser, "browser for: " . substr($ua, 0, 40));
    is($info->{os}, $os,       "os for: " . substr($ua, 0, 40));
    is($info->{device}, $device, "device for: " . substr($ua, 0, 40));
    is($info->{kind}, $kind,   "kind for: " . substr($ua, 0, 40));
}

my $win11 = LogHawk::Stats::parse_ua('Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0');
is($win11->{os_version}, '10/11', 'Windows NT 10.0 version mapping');
my $mac = LogHawk::Stats::parse_ua('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/604.1');
is($mac->{os_version}, '10.15.7', 'macOS underscore version normalized');
my $droid = LogHawk::Stats::parse_ua('Mozilla/5.0 (Linux; Android 14; Pixel 8) Chrome/119 Mobile Safari');
is($droid->{os_version}, '14', 'Android version captured');

# ---------------------------------------------------------------------------
# Aggregation over synthetic records
# ---------------------------------------------------------------------------

my @recs = (
    { type => 'combined', ts => ymd_epoch(2025, 11, 17, 10, 0, 0, 0),
      ip => '10.0.0.1', path => '/', status => 200, bytes => 1000,
      method => 'GET', ua => 'curl/8.4.0' },
    { type => 'combined', ts => ymd_epoch(2025, 11, 17, 10, 0, 30, 0),
      ip => '10.0.0.1', path => '/login', status => 404, bytes => 200,
      method => 'POST', ua => 'curl/8.4.0' },
    { type => 'combined', ts => ymd_epoch(2025, 11, 17, 10, 1, 0, 0),
      ip => '10.0.0.2', path => '/', status => 200, bytes => 3000,
      method => 'GET', ua => 'Mozilla/5.0 (X11; Linux x86_64) Firefox/122.0' },
    { type => 'combined', ts => ymd_epoch(2025, 11, 18, 10, 0, 0, 0),
      ip => '10.0.0.3', path => '/api/v1/orders', status => 500, bytes => 50,
      method => 'GET', ua => 'Mozilla/5.0 (compatible; Googlebot/2.1)' },
    { type => 'json', ts => ymd_epoch(2025, 11, 18, 10, 0, 5, 0),
      ip => '10.0.0.3', path => '/health', status => 200, bytes => 15,
      method => 'GET', ua => undef, level => 'info' },
    { type => 'combined', ts => ymd_epoch(2025, 11, 18, 10, 0, 59, 0),
      ip => '10.0.0.3', path => '/api/v1/orders', status => 500, bytes => 50,
      method => 'GET', ua => 'Mozilla/5.0 (compatible; Googlebot/2.1)' },
);

my $s = LogHawk::Stats->analyze(\@recs);
my $sum = $s->summary;

is($sum->{overview}{total}, 6, 'total counted');
is($sum->{overview}{errors}, 3, 'error count (404 + 2x500)');
is($sum->{overview}{error_rate}, '50.0', 'error rate percent');
is($sum->{overview}{bytes_total}, 4315, 'bytes total');
is($sum->{overview}{uniq_ips}, 3, 'unique ips');
is($sum->{overview}{uniq_urls}, 4, 'unique urls');
is($sum->{overview}{first_iso}, '2025-11-17T10:00:00Z', 'first ts');
is($sum->{overview}{last_iso}, '2025-11-18T10:00:59Z', 'last ts');

is($sum->{status}{classes}{'2xx'}, 3, '2xx class count');
is($sum->{status}{classes}{'4xx'}, 1, '4xx class count');
is($sum->{status}{classes}{'5xx'}, 2, '5xx class count');
is($sum->{status}{codes}{200}, 3, 'code 200 count');
is($sum->{status}{codes}{500}, 2, 'code 500 count');
is($sum->{status}{codes_top}[0][0], 200, 'top code is 200');
is($sum->{status}{codes_top}[0][1], 3, 'top code count');

is($sum->{top_ips}[0][0], '10.0.0.3', 'top ip');
is($sum->{top_ips}[0][1], 3, 'top ip count');
is($sum->{top_ips}[0][2], 115, 'top ip bytes');
is($sum->{top_urls}[0][0], '/', 'top url (tie broken lexicographically)');
is($sum->{top_urls}[0][1], 2, 'top url count');
is($sum->{top_urls}[1][0], '/api/v1/orders', 'second url');

is(scalar @{ $sum->{days} }, 2, 'two days present');
is($sum->{days}[0][0], '2025-11-17', 'first day label');
is($sum->{days}[0][1], 3, 'first day requests');
is($sum->{days}[0][2], 4200, 'first day bytes');
is($sum->{days}[1][2], 115, 'second day bytes');

is($sum->{browsers}[0][0], 'Googlebot', 'top browser (tie -> key asc)');
is($sum->{oses}[0][0], 'Other', 'top os for tools');
my %kinds = map { $_->[0] => $_->[1] } @{ $sum->{ua_kinds} };
is($kinds{tool}, 2, 'ua kind tool count');
is($kinds{bot}, 2, 'ua kind bot count');
is($kinds{browser}, 1, 'ua kind browser count');
is($sum->{methods}[0][0], 'GET', 'top method');
is($sum->{overview}{types}{combined}, 5, 'type counter combined');
is($sum->{overview}{types}{json}, 1, 'type counter json');

# peak detection
ok($sum->{overview}{peak_minute}, 'peak minute computed');
is($sum->{overview}{peak_minute}{count}, 3, 'peak minute count (10:00 bucket)');
is($sum->{overview}{peak_minute}{label}, '2025-11-18 10:00', 'peak minute label');

# ---------------------------------------------------------------------------
# top() ordering, ties and bounds
# ---------------------------------------------------------------------------

my $hash = { a => 5, b => 5, c => 9, d => 1, e => 3 };
my $t5 = LogHawk::Stats->top($hash, 5);
is_deeply($t5, [ ['c', 9], ['a', 5], ['b', 5], ['e', 3], ['d', 1] ], 'top full ordering');
my $t2 = LogHawk::Stats->top($hash, 2);
is_deeply($t2, [ ['c', 9], ['a', 5] ], 'top bounded (tie -> key asc)');
my $tmin = LogHawk::Stats->top($hash, 5, 5);
is_deeply($tmin, [ ['c', 9], ['a', 5], ['b', 5] ], 'top with min threshold');
is_deeply(LogHawk::Stats->top({}, 10), [], 'top of empty hash');
is_deeply(LogHawk::Stats->top($hash, 0), [], 'top n=0 returns empty');

# ---------------------------------------------------------------------------
# durations
# ---------------------------------------------------------------------------

my @dur_recs = map {
    { type => 'json', ts => ymd_epoch(2025, 11, 18, 12, 0, $_, 0),
      ip => '10.9.9.9', path => '/slow', status => 200, bytes => 10,
      duration_ms => $_ * 10 }
} 1 .. 20;

my $sum2 = LogHawk::Stats->analyze(\@dur_recs)->summary;
ok($sum2->{durations}, 'durations block present');
is($sum2->{durations}{count}, 20, 'duration sample count');
is($sum2->{durations}{max_ms}, 200, 'duration max');
is($sum2->{durations}{p50_ms}, 105, 'duration p50');
is($sum2->{durations}{p95_ms}, 191, 'duration p95');

# ---------------------------------------------------------------------------
# integration: parser -> stats on a mixed blob
# ---------------------------------------------------------------------------

my $blob = join("\n",
    '172.16.0.5 - - [18/Nov/2025:09:00:00 +0000] "GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"',
    '{"ts":"2025-11-18T09:00:10Z","level":"error","msg":"db down","status":500,"bytes":0}',
    'Nov 18 09:00:20 db01 mysqld[777]: Aborted connection 42 to db: user failed',
);
my $p2 = LogHawk::Parser->new;
my @recs2;
for my $line (split /\n/, $blob) {
    my $r = $p2->parse_line($line);
    push @recs2, $r if $r;
}
is(scalar @recs2, 3, 'mixed blob all parsed');

my $sum3 = LogHawk::Stats->analyze(\@recs2)->summary;
is($sum3->{overview}{total}, 3, 'mixed blob total');
is($sum3->{status}{codes}{500}, 1, 'mixed blob json status mapped');
is($sum3->{status}{codes}{200}, 1, 'mixed blob combined status mapped');
ok($sum3->{browsers}[0][0] eq 'Chrome', 'mixed blob ua classified');

# ---------------------------------------------------------------------------
# latency profiles: per-path percentiles + slowest requests
# ---------------------------------------------------------------------------

my @lat_recs = (
    (map { { type => 'combined', ts => ymd_epoch(2025, 11, 18, 12, 0, $_, 0),
             ip => '10.0.0.1', path => '/api/report', url => '/api/report',
             status => 200, bytes => 100, duration_ms => 10 + $_ } } 0 .. 9),
    (map { { type => 'combined', ts => ymd_epoch(2025, 11, 18, 12, 1, $_, 0),
             ip => '10.0.0.2', path => '/api/export', url => '/api/export',
             status => 200, bytes => 100, duration_ms => 500 + $_ * 20 } } 0 .. 9),
);

my $lat_sum = LogHawk::Stats->analyze(\@lat_recs)->summary;
ok($lat_sum->{latency}, 'latency block present');
is(scalar @{ $lat_sum->{latency}{paths} }, 2, 'two latency paths');
is($lat_sum->{latency}{paths}[0][0], '/api/export', 'highest-p95 path listed first');
is($lat_sum->{latency}{paths}[0][1], 10, 'timed request count');
cmp_ok($lat_sum->{latency}{paths}[0][4], '>=', 660, 'export p95 in the slow band');
cmp_ok($lat_sum->{latency}{paths}[0][5], '==', 680, 'export max');
cmp_ok($lat_sum->{latency}{paths}[1][4], '<=', 20, 'report p95 fast');
cmp_ok($lat_sum->{latency}{paths}[1][5], '==', 19, 'report max');

is(scalar @{ $lat_sum->{latency}{slowest} }, 10, 'slowest list bounded at 10');
is($lat_sum->{latency}{slowest}[0][0], 680, 'slowest request duration');
is($lat_sum->{latency}{slowest}[0][1], '/api/export', 'slowest request path');
is($lat_sum->{latency}{slowest}[0][2], '10.0.0.2', 'slowest request ip');
cmp_ok($lat_sum->{latency}{slowest}[1][0], '<=', 680, 'slowest list sorted descending');

ok(!defined LogHawk::Stats->analyze(
    [ { type => 'combined', path => '/x', status => 200, bytes => 1 } ]
)->summary->{latency}, 'no durations -> no latency block');

done_testing();
