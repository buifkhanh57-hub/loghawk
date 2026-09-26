#!/usr/bin/env perl
# t/series.t - LogHawk::Series bucketing, gap filling and charts
use strict;
use utf8;    # compare sparkline output as characters, not bytes
use warnings;

use Test::More;
use FindBin;
use lib "$FindBin::Bin/../lib";

use LogHawk::Series qw(bucketize unit_seconds ascii_chart sparkline resample);
use LogHawk::Util qw(ymd_epoch);

is(unit_seconds('minute'), 60, 'unit minute');
is(unit_seconds('hour'), 3600, 'unit hour');
is(unit_seconds('day'), 86400, 'unit day');
is(unit_seconds('second'), 1, 'unit second');
is(unit_seconds('900'), 900, 'raw seconds unit');
eval { unit_seconds('fortnight') };
like($@, qr/unknown series unit/, 'unknown unit croaks');
eval { unit_seconds('0') };
like($@, qr/unknown series unit/, 'zero unit croaks');

# ---------------------------------------------------------------------------
# bucketize basics
# ---------------------------------------------------------------------------

my $base = ymd_epoch(2025, 11, 18, 10, 0, 0, 0);
my @recs = map {
    { ts => $base + $_ * 30, status => $_ == 7 ? 500 : 200, bytes => 100, type => 'combined' }
} 0 .. 11;   # 12 records, one every 30s, spanning 5.5 minutes

my $res = bucketize(\@recs, unit => 'minute');
is($res->{unit}, 'minute', 'unit echoed');
is($res->{seconds}, 60, 'seconds echoed');
is($res->{value}, 'count', 'value echoed');
is(scalar @{ $res->{series} }, 6, 'gap filled to 6 minute buckets');
is($res->{stats}{total}, 12, 'all records bucketed');
is($res->{stats}{buckets}, 6, 'bucket stat');
is($res->{series}[0]{label}, '2025-11-18 10:00', 'first bucket label');
is($res->{series}[0]{count}, 2, 'first bucket count');
is($res->{series}[1]{count}, 2, 'second bucket count');
is($res->{series}[3]{value}, 2, 'value mirrors count');
is($res->{series}[3]{bytes}, 200, 'bucket bytes');
is($res->{series}[5]{count}, 2, 'last bucket count');
is($res->{stats}{max}, 2, 'max bucket value');
is($res->{stats}{mean}, 2, 'mean bucket value');
ok($res->{stats}{peak} == 2 && defined $res->{stats}{peak_label}, 'peak stats');

# value => bytes
$res = bucketize(\@recs, unit => 'minute', value => 'bytes');
is($res->{series}[0]{value}, 200, 'bytes value mode');

# value => errors
$res = bucketize(\@recs, unit => 'minute', value => 'errors');
my @err_counts = map { $_->{value} } @{ $res->{series} };
is_deeply(\@err_counts, [0, 0, 0, 1, 0, 0], 'errors value mode (500 at +3.5m)');
is($res->{series}[3]{count}, 2, 'count still tracked alongside errors');

# no-fill keeps only occupied buckets
$res = bucketize(\@recs, unit => 'minute', fill => 0);
is(scalar @{ $res->{series} }, 6, 'no-fill occupied buckets');
my @epochs = map { $_->{epoch} } @{ $res->{series} };
my @sorted = sort { $a <=> $b } @epochs;
is_deeply(\@epochs, \@sorted, 'no-fill series sorted');

# gap-filling across a hole
my @sparse = (
    { ts => $base,        status => 200, bytes => 10, type => 'combined' },
    { ts => $base + 300,  status => 200, bytes => 10, type => 'combined' },
);
$res = bucketize(\@sparse, unit => 'minute');
is(scalar @{ $res->{series} }, 6, 'hole filled with zero buckets');
is($res->{series}[1]{value}, 0, 'hole bucket value zero');
is($res->{series}[2]{count}, 0, 'hole bucket count zero');

# empty input
$res = bucketize([], unit => 'hour');
is(scalar @{ $res->{series} }, 0, 'empty records -> empty series');
is($res->{stats}{total}, 0, 'empty stats total');

# ---------------------------------------------------------------------------
# level-based error detection in buckets
# ---------------------------------------------------------------------------

my @lvl = (
    { ts => $base, status => 200, bytes => 1, level => 'info',    type => 'json' },
    { ts => $base + 5, status => 200, bytes => 1, level => 'error', type => 'json' },
    { ts => $base + 10, status => 503, bytes => 1, level => undef,  type => 'combined' },
);
$res = bucketize(\@lvl, unit => 'minute', value => 'errors');
is($res->{series}[0]{value}, 2, 'level error + 5xx both counted once each per record');

# ---------------------------------------------------------------------------
# sparkline
# ---------------------------------------------------------------------------

my $spark = sparkline([0, 2, 4, 6, 8]);
is(length $spark, 5, 'sparkline length');
ok($spark =~ /\S/, 'sparkline has content');
is(sparkline([]), '', 'sparkline empty input');
my $wide = sparkline([0 .. 50], 10);
is(length $wide, 10, 'sparkline downsampled width');
ok($wide =~ /\A / || $wide =~ /\A▁/, 'sparkline starts near-zero');

# ---------------------------------------------------------------------------
# ascii chart
# ---------------------------------------------------------------------------

my @chart_buckets = map {
    { epoch => $base + $_ * 60, label => sprintf('2025-11-18 10:%02d', $_),
      value => ($_ + 1) * 10, count => ($_ + 1) * 10, bytes => 0, errors => 0 }
} 0 .. 4;

my $chart = ascii_chart(\@chart_buckets, bar_width => 10, value => 'count');
my @lines = split /\n/, $chart;
is(scalar @lines, 5, 'chart row count');
like($lines[0], qr/10:00\s+#{1,3}\s+10$/, 'first row short bar');
like($lines[4], qr/#{10}\s+50$/, 'last row full bar');
is(ascii_chart([]), '', 'chart empty input');

my $many = ascii_chart([map { { epoch => $base + $_ * 60,
    label => "b$_", value => $_ + 1, count => 1, bytes => 0, errors => 0 } } 0 .. 99],
    rows => 10);
is(scalar split(/\n/, $many), 10, 'chart downsamples to rows');

# ---------------------------------------------------------------------------
# resample
# ---------------------------------------------------------------------------

my $minute = bucketize(\@recs, unit => 'minute');
my $hourly = resample($minute->{series}, 3600);
is(scalar @$hourly, 1, 'resample minute -> hour single bucket');
is($hourly->[0]{count}, 12, 'resample sums counts');
is($hourly->[0]{bytes}, 1200, 'resample sums bytes');
eval { resample([], 0) };
like($@, qr/positive bucket width/, 'resample rejects zero width');

done_testing();
