#!/usr/bin/env perl
# t/export.t - LogHawk::Export CSV/JSON serialization + LogHawk::Filters
use strict;
use warnings;

use Test::More;
use FindBin;
use lib "$FindBin::Bin/../lib";

use LogHawk::Export qw(csv_escape);
use LogHawk::Filters;
use JSON::PP ();
use LogHawk::Util qw(ymd_epoch);

# ---------------------------------------------------------------------------
# CSV escaping
# ---------------------------------------------------------------------------

is(csv_escape('plain'), 'plain', 'plain field untouched');
is(csv_escape('has,comma'), '"has,comma"', 'comma quoted');
is(csv_escape('has"quote'), '"has""quote"', 'quote doubled');
is(csv_escape("line1\nline2"), "\"line1\nline2\"", 'newline quoted');
is(csv_escape(undef), '', 'undef -> empty');
is(csv_escape(42), '42', 'number passthrough');

# ---------------------------------------------------------------------------
# records -> csv
# ---------------------------------------------------------------------------

my @recs = (
    { type => 'combined', ts => ymd_epoch(2025, 11, 18, 10, 0, 0, 0),
      ts_iso => '2025-11-18T10:00:00Z', ip => '10.0.0.1', user => undef,
      method => 'GET', url => '/a,b', status => 200, bytes => 512,
      referer => '-', ua => 'curl/8.4.0', level => undef, message => undef,
      raw => 'RAWLINE' },
    { type => 'json', ts => ymd_epoch(2025, 11, 18, 10, 0, 5, 0),
      ts_iso => '2025-11-18T10:00:05Z', ip => '10.0.0.2', method => 'POST',
      url => '/x', status => 500, bytes => 0, level => 'error',
      message => 'db said "no"', data => { shard => 3 } },
);

my $csv = LogHawk::Export::records_to_csv(\@recs);
my @rows = split /\n/, $csv;
is(scalar @rows, 3, 'csv header + 2 rows');
like($rows[0], qr/^ts_iso,type,ip/, 'csv header order');
like($rows[1], qr/"\/a,b"/, 'csv url with comma quoted');
like($rows[2], qr/""no""/, 'csv embedded quotes doubled');
ok($rows[1] !~ /RAWLINE/, 'raw line excluded from export');

my $csv2 = LogHawk::Export::records_to_csv(\@recs, ['ip', 'status']);
my @rows2 = split /\n/, $csv2;
is($rows2[0], 'ip,status', 'csv custom fields header');
like($rows2[1], qr/^10\.0\.0\.1,200$/, 'csv custom fields row');

# ---------------------------------------------------------------------------
# records -> json / ndjson
# ---------------------------------------------------------------------------

my $json = LogHawk::Export::records_to_json(\@recs);
my $data = JSON::PP->new->decode($json);
is($data->{meta}{count}, 2, 'json meta count');
is($data->{meta}{format}, 'loghawk-records/1', 'json meta format');
is(scalar @{ $data->{records} }, 2, 'json record count');
is($data->{records}[0]{ip}, '10.0.0.1', 'json record field');
ok(!exists $data->{records}[0]{raw}, 'json record strips raw');
is($data->{records}[1]{data}{shard}, 3, 'json data block preserved');
ok(!exists $data->{records}[1]{user}, 'undef optional fields omitted');

my $compact = LogHawk::Export::records_to_json(\@recs, 0);
ok(index($compact, "\n") < 20, 'compact json is one line');

my $nd = LogHawk::Export::records_to_ndjson(\@recs);
my @nd_lines = split /\n/, $nd;
is(scalar @nd_lines, 2, 'ndjson line count');
my $first = JSON::PP->new->decode($nd_lines[0]);
is($first->{status}, 200, 'ndjson first record decodes');
my $second = JSON::PP->new->decode($nd_lines[1]);
is($second->{level}, 'error', 'ndjson second record decodes');

# summary + series serialization
my $summary = { overview => { total => 2, bytes_human => '512 B' } };
my $sj = JSON::PP->new->decode(LogHawk::Export::summary_to_json($summary));
is($sj->{summary}{overview}{total}, 2, 'summary json round trip');

my $series_res = {
    unit => 'minute', value => 'count', seconds => 60,
    series => [ { label => '2025-11-18 10:00', epoch => ymd_epoch(2025, 11, 18, 10, 0, 0, 0),
                  value => 2, count => 2, bytes => 512, errors => 0 } ],
};
my $sc = LogHawk::Export::series_to_csv($series_res, 'value');
my @sc_rows = split /\n/, $sc;
is(scalar @sc_rows, 2, 'series csv rows');
like($sc_rows[0], qr/^label,epoch,value,count,bytes,errors$/, 'series csv header');
like($sc_rows[1], qr/^2025-11-18 10:00,\d+,2,2,512,0$/, 'series csv data row');

# write_file
my $tmp = "/tmp/loghawk_export_test_$$.txt";
LogHawk::Export::write_file($tmp, "hello loghawk\n");
ok(-f $tmp, 'write_file created file');
open(my $fh, '<', $tmp) or die $!;
my $content = do { local $/; <$fh> };
close $fh;
is($content, "hello loghawk\n", 'write_file content round trip');
unlink $tmp;
eval { LogHawk::Export::write_file('/no/such/dir/file.txt', 'x') };
like($@, qr/cannot write/, 'write_file croaks on bad path');

# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------

my @frecs = (
    { type => 'combined', ts => ymd_epoch(2025, 11, 18, 10, 0, 0, 0),
      ip => '10.1.2.3', url => '/api/users', path => '/api/users',
      method => 'GET', status => 200, bytes => 100, level => undef },
    { type => 'combined', ts => ymd_epoch(2025, 11, 18, 10, 1, 0, 0),
      ip => '203.0.113.9', url => '/wp-login.php', path => '/wp-login.php',
      method => 'POST', status => 404, bytes => 200, level => undef },
    { type => 'combined', ts => ymd_epoch(2025, 11, 18, 10, 2, 0, 0),
      ip => '203.0.113.10', url => '/.env', path => '/.env',
      method => 'GET', status => 500, bytes => 300, level => 'error' },
    { type => 'json', ts => undef, ip => '10.1.2.3', status => 200, bytes => 5 },
);

my $m = LogHawk::Filters->new;
is($m->count(\@frecs), 4, 'empty filter matches everything');
is($m->to_string, 'none', 'empty filter describe');

is(LogHawk::Filters->new(status => '5xx')->count(\@frecs), 1, 'status class 5xx');
is(LogHawk::Filters->new(status => '200,500')->count(\@frecs), 3, 'status exact list');
is(LogHawk::Filters->new(status => '4xx,5xx')->count(\@frecs), 2, 'status mixed classes');
is(LogHawk::Filters->new(exclude_status => '2xx')->count(\@frecs), 2, 'exclude_status');
is(LogHawk::Filters->new(ip => '10.1.2.3')->count(\@frecs), 2, 'ip exact (incl ts-less)');
is(LogHawk::Filters->new(ip => '203.0.113.0/24')->count(\@frecs), 2, 'ip CIDR');
is(LogHawk::Filters->new(ip => '203.0.113.*')->count(\@frecs), 2, 'ip glob');
is(LogHawk::Filters->new(ip => '^203\.')->count(\@frecs), 2, 'ip regex fragment');
is(LogHawk::Filters->new(url_regex => '\.php$|\.env')->count(\@frecs), 2, 'url regex');
is(LogHawk::Filters->new(url => '/api')->count(\@frecs), 1, 'url substring');
is(LogHawk::Filters->new(method => 'post')->count(\@frecs), 1, 'method case-insensitive');
is(LogHawk::Filters->new(level => 'error')->count(\@frecs), 1, 'level match');
is(LogHawk::Filters->new(min_bytes => 200)->count(\@frecs), 2, 'min_bytes');
is(LogHawk::Filters->new(max_bytes => 100)->count(\@frecs), 2, 'max_bytes');

my $f = LogHawk::Filters->new(
    status => '5xx',
    ip     => '203.0.113.10',
);
is($f->count(\@frecs), 1, 'AND combination');
like($f->to_string, qr/status in \[5xx\]; ip in/, 'chained describe');

my $since = LogHawk::Filters->new(since => '2025-11-18 10:01:00');
is($since->count(\@frecs), 2, 'since filter');
my $win = LogHawk::Filters->new(since => '2025-11-18 10:00:30', until => '2025-11-18 10:01:30');
is($win->count(\@frecs), 1, 'since+until window');
is(LogHawk::Filters->new(since => '2020-01-01')->count(\@frecs), 3, 'absolute since matches all timed');
is(LogHawk::Filters->new(since => '-1h')->count([ $frecs[3] ]), 0, 'time filter drops ts-less');

eval { LogHawk::Filters->new(status => '5xxs') };
like($@, qr/invalid status filter/, 'bad status croaks');
eval { LogHawk::Filters->new(url_regex => '(') };
like($@, qr/invalid regex/, 'bad regex croaks');
eval { LogHawk::Filters->new(level => 'shouting') };
like($@, qr/invalid --level/, 'bad level croaks');
eval { LogHawk::Filters->new(since => 'never') };
like($@, qr/invalid --since/, 'bad since croaks');
eval { LogHawk::Filters->new(ip => '999.1.1.1') };
like($@, qr/invalid IP literal/, 'bad ip croaks');

my $or = LogHawk::Filters->any(
    LogHawk::Filters->new(status => '404'),
    LogHawk::Filters->new(ip => '10.1.2.3', url => '/api'),
);
is($or->count(\@frecs), 2, 'any() OR combination');

# IPv4 helpers
is(LogHawk::Filters::ipv4_to_int('0.0.0.0'), 0, 'ipv4 zero');
is(LogHawk::Filters::ipv4_to_int('255.255.255.255'), 4294967295, 'ipv4 max');
ok(LogHawk::Filters::cidr_match('10.1.2.3', '10.0.0.0/8'), 'cidr /8 match');
ok(!LogHawk::Filters::cidr_match('11.1.2.3', '10.0.0.0/8'), 'cidr /8 non-match');
ok(LogHawk::Filters::cidr_match('10.1.2.3', '10.1.2.3'), 'cidr /32 match');
ok(LogHawk::Filters::cidr_match('203.0.113.9', '0.0.0.0/0'), 'cidr /0 matches all');
ok(!defined LogHawk::Filters::cidr_match('not-an-ip', '10.0.0.0/8'), 'cidr bad input');
ok(!defined LogHawk::Filters::ipv4_to_int('256.1.1.1'), 'ipv4 octet overflow');

done_testing();
