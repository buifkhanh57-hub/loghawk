#!/usr/bin/env perl
# t/parser.t - LogHawk::Parser + LogHawk::Util time arithmetic tests
use strict;
use warnings;

use Test::More;
use FindBin;
use lib "$FindBin::Bin/../lib";

use LogHawk::Parser;
use LogHawk::Util qw(
    parse_combined_time parse_iso_time parse_datetime parse_syslog_time
    days_from_civil ymd_epoch status_class human_size human_num epoch_to_iso
    pct mean stddev percentile
);

# ---------------------------------------------------------------------------
# Util: calendar math
# ---------------------------------------------------------------------------

is(days_from_civil(1970, 1, 1), 0, 'days_from_civil epoch zero');
is(days_from_civil(2025, 11, 18), 20410, 'days_from_civil 2025-11-18');
is(ymd_epoch(2025, 11, 18, 3, 7, 12, 0), 1_763_435_232, 'ymd_epoch UTC instant');
is(ymd_epoch(2025, 11, 18, 3, 7, 12, 25200), 1_763_435_232 - 25_200,
    'ymd_epoch applies +0700 offset');

my $e = parse_combined_time('18/Nov/2025:03:07:12 +0000');
is($e, 1_763_435_232, 'parse_combined_time +0000');

$e = parse_combined_time('18/Nov/2025:03:07:12 +0700');
is($e, 1_763_435_232 - 25_200, 'parse_combined_time +0700');

$e = parse_combined_time('18/Nov/2025:03:07:12 -0530');
is($e, 1_763_435_232 + 19_800, 'parse_combined_time -0530');

ok(!defined parse_combined_time('not a time'), 'parse_combined_time rejects garbage');
ok(!defined parse_combined_time('32/XYZ/2025:99:00:00 +0000'), 'parse_combined_time rejects bad month');

is(parse_iso_time('2025-11-18T03:07:12Z'), 1_763_435_232, 'parse_iso_time Z');
is(parse_iso_time('2025-11-18T03:07:12.500Z'), 1_763_435_232, 'parse_iso_time fraction');
is(parse_iso_time('2025-11-18T10:07:12+07:00'), 1_763_435_232, 'parse_iso_time +07:00');

is(parse_datetime('-0s', 1_000_000), 1_000_000, 'parse_datetime -0s');
is(parse_datetime('-2h', 1_000_000), 1_000_000 - 7200, 'parse_datetime -2h');
is(parse_datetime('-1w', 1_000_000), 1_000_000 - 604_800, 'parse_datetime -1w');
is(parse_datetime('2025-11-18', 0), 1_763_424_000, 'parse_datetime date only');
is(parse_datetime('now', 42), 42, 'parse_datetime now');
ok(!defined parse_datetime('yesterday-ish'), 'parse_datetime unknown returns undef');

# syslog year heuristic: fixed "now" makes it deterministic
my $now = ymd_epoch(2025, 11, 18, 12, 0, 0, 0);
is(parse_syslog_time('Nov 18 03:07:12', $now), 1_763_435_232, 'syslog same year');
is(parse_syslog_time('Dec 31 23:59:59', $now), ymd_epoch(2024, 12, 31, 23, 59, 59, 0),
    'syslog future date rolls back a year');
is(parse_syslog_time('Nov 18 03:07:12', $now, 2020), ymd_epoch(2020, 11, 18, 3, 7, 12, 0),
    'syslog default_year override');

# small formatting helpers
is(human_size(0), '0 B', 'human_size zero');
is(human_size(1536), '1.5 KB', 'human_size KB');
is(human_size(5 * 1024 * 1024), '5.0 MB', 'human_size MB');
is(human_num(1_234_567), '1,234,567', 'human_num grouping');
is(pct(50, 200), '25.0', 'pct');
is(pct(5, 0), '0.0', 'pct zero denominator');
is(status_class(200), '2xx', 'status_class 200');
is(status_class(503), '5xx', 'status_class 503');
is(status_class('-'), 'unknown', 'status_class dash');
is(epoch_to_iso(1_763_435_232), '2025-11-18T03:07:12Z', 'epoch_to_iso');

is(mean([2, 4, 4, 4, 5, 5, 7, 9]), 5, 'mean');
cmp_ok(stddev([2, 4, 4, 4, 5, 5, 7, 9]), '<', 2.2, 'stddev sample formula');
cmp_ok(stddev([2, 4, 4, 4, 5, 5, 7, 9]), '>', 2.0, 'stddev lower bound');
is(percentile([10, 20, 30, 40], 50), 25, 'percentile interpolation');

# ---------------------------------------------------------------------------
# Parser: combined / common
# ---------------------------------------------------------------------------

my $p = LogHawk::Parser->new;

my $combined =
    '203.0.113.42 - alice [18/Nov/2025:03:07:12 +0000] '
  . '"GET /api/v1/users?page=2 HTTP/1.1" 200 5124 '
  . '"https://example.com/dashboard" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
  . 'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"';

my $r = $p->parse_line($combined);
ok($r, 'combined line parses');
is($r->{type}, 'combined', 'type combined');
is($r->{ip}, '203.0.113.42', 'ip field');
is($r->{ident}, undef, 'ident dash -> undef');
is($r->{user}, 'alice', 'user field');
is($r->{ts}, 1_763_435_232, 'epoch from CLF time');
is($r->{ts_iso}, '2025-11-18T03:07:12Z', 'normalized ts_iso');
is($r->{method}, 'GET', 'method');
is($r->{url}, '/api/v1/users?page=2', 'url keeps query');
is($r->{path}, '/api/v1/users', 'path strips query');
is($r->{proto}, 'HTTP/1.1', 'protocol');
is($r->{status}, 200, 'status int');
is($r->{bytes}, 5124, 'bytes int');
is($r->{referer}, 'https://example.com/dashboard', 'referer');
like($r->{ua}, qr/Chrome/, 'user agent captured');
is($r->{line_no}, 1, 'line number');

my $common = '10.1.2.3 - - [18/Nov/2025:03:08:00 +0000] "POST /login HTTP/1.1" 302 0';
$r = $p->parse_line($common);
ok($r, 'common line parses');
is($r->{type}, 'common', 'type common');
is($r->{method}, 'POST', 'common method');
is($r->{status}, 302, 'common status');
is($r->{bytes}, 0, 'common dash bytes -> 0');
ok(!defined $r->{ua}, 'common has no UA');

$r = $p->parse_line('10.0.0.9 - - [18/Nov/2025:03:09:00 +0000] "\x16\x03\x01" 400 157');
ok($r, 'binary garbage request still parses');
ok(!defined $r->{method}, 'garbage request has no method');
is($r->{url}, '\x16\x03\x01', 'garbage kept as url verbatim');
is($r->{status}, 400, 'garbage request status');

$r = $p->parse_line('10.0.0.9 - - [bogus time] "GET / HTTP/1.1" 200 1');
ok($r, 'bad timestamp still yields a record');
ok(!defined $r->{ts}, 'bad timestamp -> ts undef');

# ---------------------------------------------------------------------------
# Parser: error log, syslog, JSON
# ---------------------------------------------------------------------------

$r = $p->parse_line('[Tue Nov 18 03:10:00 2025] [error] [client 198.51.100.7] '
    . 'File does not exist: /var/www/favicon.ico');
ok($r, 'error log line parses');
is($r->{type}, 'error', 'type error');
is($r->{ts}, ymd_epoch(2025, 11, 18, 3, 10, 0, 0), 'error log epoch');
is($r->{level}, 'error', 'error level');
is($r->{ip}, '198.51.100.7', 'error log client ip');
like($r->{message}, qr/favicon/, 'error message');

$r = $p->parse_line('<34>Nov 18 03:11:22 web01 sshd[2318]: Failed password for root from 203.0.113.9 port 51234 ssh2');
ok($r, 'syslog PRI line parses');
is($r->{type}, 'syslog', 'type syslog');
is($r->{pri}, 34, 'pri captured');
is($r->{facility}, 'auth', 'facility from PRI (auth = 4)');
is($r->{level}, 'critical', 'PRI severity 2 -> critical');
is($r->{host}, 'web01', 'syslog host');
is($r->{program}, 'sshd', 'syslog program');
is($r->{pid}, 2318, 'syslog pid');
is($r->{ts}, ymd_epoch(2025, 11, 18, 3, 11, 22, 0), 'syslog epoch with heuristic year');
is($r->{ip}, '203.0.113.9', 'ip extracted from message');

$r = $p->parse_line('Nov 18 03:12:44 web01 cron[912]: (root) CMD (run-parts /etc/cron.hourly)');
ok($r, 'plain syslog parses');
is($r->{level}, 'info', 'inferred level info');
is($r->{program}, 'cron', 'program without PRI');

$r = $p->parse_line('2025-11-18T03:15:00.123Z web01 nginx: upstream timed out while reading response header');
ok($r, 'ISO syslog parses');
is($r->{type}, 'syslog', 'ISO syslog type');
is($r->{ts}, ymd_epoch(2025, 11, 18, 3, 15, 0, 0), 'ISO syslog epoch');
is($r->{level}, 'error', 'ISO syslog inferred level from message');

my $json_line = '{"@timestamp":"2025-11-18T03:35:12Z","level":"warn","msg":"slow query",'
    . '"remote_addr":"192.0.2.44","method":"GET","url":"/api/v1/orders?slow=1",'
    . '"status_code":504,"body_bytes_sent":0,"user_agent":"python-requests/2.31.0",'
    . '"duration_ms":5120,"extra_field":"kept"}';
$r = $p->parse_line($json_line);
ok($r, 'json line parses');
is($r->{type}, 'json', 'type json');
is($r->{ts}, ymd_epoch(2025, 11, 18, 3, 35, 12, 0), 'json @timestamp');
is($r->{level}, 'warning', 'level warn -> warning');
is($r->{message}, 'slow query', 'json msg');
is($r->{ip}, '192.0.2.44', 'json remote_addr mapping');
is($r->{method}, 'GET', 'json method');
is($r->{url}, '/api/v1/orders?slow=1', 'json url');
is($r->{path}, '/api/v1/orders', 'json path');
is($r->{status}, 504, 'json status_code mapping');
is($r->{bytes}, 0, 'json body_bytes_sent');
is($r->{duration_ms}, 5120, 'json duration_ms');
is($r->{data}{extra_field}, 'kept', 'unknown json keys preserved in data');

$r = $p->parse_line('{"ts_epoch":1763435232,"level":"info","msg":"boot","status":"200","bytes":"256"}');
ok($r, 'epoch-key json parses');
is($r->{ts}, 1_763_435_232, 'json ts_epoch mapping');
is($r->{status}, 200, 'json string status coerced');
is($r->{bytes}, 256, 'json string bytes coerced');

ok(!defined $p->parse_line('{"broken json'), 'malformed json skipped');
ok(!defined $p->parse_line('total garbage not a log line'), 'unparsable text skipped');
ok(!defined $p->parse_line(''), 'empty line skipped');
ok(!defined $p->parse_line('completely unrelated text'), 'unrecognized line skipped');

# ---------------------------------------------------------------------------
# Counters and files
# ---------------------------------------------------------------------------

my $st = $p->stats;
is($st->{lines}, 14, 'line counter');
is($st->{blank}, 1, 'blank counter');
is($st->{parsed}, 10, 'parsed counter');
is($st->{skipped}, 3, 'skipped counter');
is($st->{by_type}{combined}, 1, 'by_type combined');
is($st->{by_type}{common}, 3, 'by_type common');
is($st->{by_type}{error}, 1, 'by_type error');
is($st->{by_type}{syslog}, 3, 'by_type syslog');
is($st->{by_type}{json}, 2, 'by_type json');
ok(@{ $st->{errors} } >= 2, 'error samples retained');
like($st->{errors}[-1]{text}, qr/unrelated/, 'sample keeps the line text');

is(LogHawk::Parser->new->detect_type($combined), 'combined', 'detect_type combined');
is(LogHawk::Parser->new->detect_type($common), 'common', 'detect_type common');
is(LogHawk::Parser->new->detect_type($json_line), 'json', 'detect_type json');
is(LogHawk::Parser->new->detect_type('<34>Nov 18 03:11:22 h p[1]: x'), 'syslog', 'detect_type syslog');
is(LogHawk::Parser->new->detect_type('nonsense'), 'unknown', 'detect_type unknown');

# parse_file + parse_fh round trip
use File::Temp qw(tempfile);
my ($tfh, $tfname) = tempfile(UNLINK => 1);
print {$tfh} $combined, "\n", $common, "\n", "\n", 'garbage line', "\n";
close $tfh;

my $p2 = LogHawk::Parser->new;
my @seen;
$p2->parse_file($tfname, sub { push @seen, $_[0] if $_[0] });
is(scalar @seen, 2, 'parse_file callback count');
is($p2->stats->{skipped}, 1, 'parse_file skip counter');
is($seen[0]{url}, '/api/v1/users?page=2', 'parse_file record content');

my $p3 = LogHawk::Parser->new(keep_raw => 0);
open(my $fh2, '<', $tfname) or die $!;
$p3->parse_fh($fh2);
close $fh2;
is($p3->stats->{parsed}, 2, 'parse_fh counts');

eval { LogHawk::Parser->new->parse_file('/no/such/file/anywhere.log') };
like($@, qr/cannot read/, 'parse_file croaks on missing file');

done_testing();
