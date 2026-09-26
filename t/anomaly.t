#!/usr/bin/env perl
# t/anomaly.t - LogHawk::Anomaly rolling z-score detection tests
use strict;
use warnings;

use Test::More;
use FindBin;
use lib "$FindBin::Bin/../lib";

use LogHawk::Anomaly;
use LogHawk::Util qw(ymd_epoch epoch_to_label);

# ---------------------------------------------------------------------------
# construction / validation
# ---------------------------------------------------------------------------

my $det = LogHawk::Anomaly->new;
is($det->{window}, 30, 'default window');
is($det->{threshold}, 3.0, 'default threshold (medium)');
is($det->{mode}, 'spikes', 'default mode');
is($det->{min_history}, 10, 'default min_history');

is(LogHawk::Anomaly->new(sensitivity => 'low')->{threshold},    4.0, 'sensitivity low');
is(LogHawk::Anomaly->new(sensitivity => 'high')->{threshold},   2.0, 'sensitivity high');
is(LogHawk::Anomaly->new(threshold => 2.5)->{threshold},        2.5, 'explicit threshold wins');
is(LogHawk::Anomaly::sensitivity_threshold('medium'), 3.0, 'sensitivity_threshold helper');

eval { LogHawk::Anomaly->new(sensitivity => 'turbo') };
like($@, qr/unknown sensitivity/, 'bad sensitivity dies');
eval { LogHawk::Anomaly->new(mode => 'sideways') };
like($@, qr/unknown mode/, 'bad mode dies');
eval { LogHawk::Anomaly->new(window => 1) };
like($@, qr/window must be/, 'tiny window dies');

# ---------------------------------------------------------------------------
# series builders
# ---------------------------------------------------------------------------

sub mk_series {
    my (@values) = @_;
    my $base = ymd_epoch(2025, 11, 18, 3, 0, 0, 0);
    my @s;
    for my $i (0 .. $#values) {
        my $e = $base + $i * 60;
        push @s, {
            epoch => $e,
            label => epoch_to_label($e, 'minute'),
            value => $values[$i],
            count => $values[$i],
            bytes => 0,
            errors => 0,
        };
    }
    return \@s;
}

# ---------------------------------------------------------------------------
# basic spike detection
# ---------------------------------------------------------------------------

my @flat = (50) x 40;
my $series = mk_series(@flat, 200, 55, 48);
my $res = LogHawk::Anomaly->new->detect($series);

is(scalar @{ $res->{points} }, 1, 'single spike detected');
my $p = $res->{points}[0];
is($p->{value}, 200, 'spike value');
is($p->{label}, '2025-11-18 03:40', 'spike label (index 40)');
is($p->{direction}, 'up', 'spike direction');
ok($p->{zscore} > 3, "z-score above threshold ($p->{zscore})");
is($p->{baseline_mean}, 50, 'baseline mean of flat run');
is($p->{baseline_sd}, 0, 'flat baseline sd');
is($p->{severity}, 'critical', 'flat-baseline spike is critical (z=150)');

is(scalar @{ $res->{events} }, 1, 'one event merged');
my $ev = $res->{events}[0];
is($ev->{buckets}, 1, 'event length 1');
is($ev->{peak_value}, 200, 'event peak');
ok($res->{risk} > 3, 'risk score reflects the spike');

# clean series -> no anomalies
$res = LogHawk::Anomaly->new->detect(mk_series((50) x 45));
is(scalar @{ $res->{points} }, 0, 'no anomalies on constant series');
is_deeply($res->{events}, [], 'events empty array');
is($res->{risk}, 0, 'risk zero on constant series');

# ---------------------------------------------------------------------------
# sensitivity levels (deterministic baseline: 45/55 alternation, sd ~5.06)
# ---------------------------------------------------------------------------

my @alt = map { $_ % 2 ? 55 : 45 } 0 .. 39;
$series = mk_series(@alt, 68);   # z = 18 / 5.06 ~ 3.56
my $med = LogHawk::Anomaly->new(sensitivity => 'medium')->detect($series)->{points};
my $low = LogHawk::Anomaly->new(sensitivity => 'low')->detect($series)->{points};
is(scalar @$med, 1, 'medium sensitivity catches moderate spike (z~3.56)');
is(scalar @$low, 0, 'low sensitivity ignores moderate spike');

# ---------------------------------------------------------------------------
# dips and both modes
# ---------------------------------------------------------------------------

$series = mk_series((50) x 40, 0, 52);
$res = LogHawk::Anomaly->new(mode => 'spikes')->detect($series);
is(scalar @{ $res->{points} }, 0, 'dip not flagged in spikes mode');

$res = LogHawk::Anomaly->new(mode => 'dips')->detect($series);
is(scalar @{ $res->{points} }, 1, 'dip flagged in dips mode');
is($res->{points}[0]{direction}, 'down', 'dip direction');
ok($res->{points}[0]{zscore} < 0, 'dip z-score negative');

$res = LogHawk::Anomaly->new(mode => 'both')->detect(mk_series((50) x 40, 0, 200));
is(scalar @{ $res->{points} }, 2, 'both mode catches dip and spike');

# ---------------------------------------------------------------------------
# event merging
# ---------------------------------------------------------------------------

$series = mk_series((50) x 40, 120, 150, 90, 55);
$res = LogHawk::Anomaly->new->detect($series);
is(scalar @{ $res->{events} }, 1, 'consecutive spikes merged into one event');
my $ev2 = $res->{events}[0];
is($ev2->{buckets}, 2, 'event spans 2 buckets');
is($ev2->{peak_value}, 150, 'event peak value');
like($ev2->{start_label}, qr/03:40/, 'event start label');
like($ev2->{end_label},   qr/03:41/, 'event end label');

$series = mk_series((50) x 40, 120, 50, 130, 55);
$res = LogHawk::Anomaly->new->detect($series);
is(scalar @{ $res->{events} }, 2, 'separated spikes stay separate events');

# ---------------------------------------------------------------------------
# min_history gate
# ---------------------------------------------------------------------------

$series = mk_series(10, 500, 500, 500, 500, 500);
$res = LogHawk::Anomaly->new(min_history => 10)->detect($series);
is(scalar @{ $res->{points} }, 0, 'no detection before min_history baseline points');

$res = LogHawk::Anomaly->new(min_history => 3, window => 30)->detect(
    mk_series(10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 100)
);
is(scalar @{ $res->{points} }, 1, 'detection once baseline is long enough');

# ---------------------------------------------------------------------------
# zero baseline (sd = 0 path) and empty input
# ---------------------------------------------------------------------------

$series = mk_series((0) x 30, 5, 0);
$res = LogHawk::Anomaly->new->detect($series);
is(scalar @{ $res->{points} }, 1, 'spike out of zero baseline detected (sd_eff=1)');
is($res->{points}[0]{value}, 5, 'zero-baseline spike value');

$res = LogHawk::Anomaly->new->detect([]);
is(scalar @{ $res->{points} }, 0, 'empty series -> no points');
is($res->{risk}, 0, 'empty series -> risk 0');

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

my $point = {
    label => '2025-11-18 03:41', value => 412, baseline_mean => 9.6,
    zscore => 7.31, direction => 'up', severity => 'critical',
};
like(LogHawk::Anomaly->describe_point($point),
    qr/03:41  value 412 vs baseline 9.60 \(z=7.31, up, critical\)/,
    'describe_point formatting');

my $event = {
    start_label => '2025-11-18 03:41', end_label => '2025-11-18 03:42',
    buckets => 2, peak_value => 412, peak_z => 7.31, severity => 'critical',
};
like(LogHawk::Anomaly->describe_event($event),
    qr/03:41 .. 2025-11-18 03:42  2 bucket\(s\), peak 412 \(z=7.31, critical\)/,
    'describe_event formatting');

is(LogHawk::Anomaly->new->risk_score(mk_series((50) x 40, 300)), 250,
    'risk_score shortcut returns max z');

# ---------------------------------------------------------------------------
# EWMA baseline method
# ---------------------------------------------------------------------------

my $ew = LogHawk::Anomaly->new(method => 'ewma');
is($ew->{method}, 'ewma', 'method option stored');
is($ew->{alpha}, 0.3, 'default alpha 0.3');
is(LogHawk::Anomaly->new->{method}, 'rolling', 'rolling is the default method');
is(LogHawk::Anomaly->new(alpha => 0.75)->{alpha}, 0.75, 'alpha override');
is(LogHawk::Anomaly->new(alpha => 1)->{alpha}, 1, 'alpha 1 accepted');

eval { LogHawk::Anomaly->new(method => 'kalman') };
like($@, qr/unknown method/, 'bad method dies');
eval { LogHawk::Anomaly->new(alpha => 0) };
like($@, qr/alpha must be/, 'alpha 0 dies');
eval { LogHawk::Anomaly->new(alpha => 1.5) };
like($@, qr/alpha must be/, 'alpha > 1 dies');
eval { LogHawk::Anomaly->new(alpha => -0.2) };
like($@, qr/alpha must be/, 'negative alpha dies');

$res = LogHawk::Anomaly->new(method => 'ewma', alpha => 0.5)->detect(mk_series((50) x 30));
is($res->{config}{method}, 'ewma', 'config echoes method');
is($res->{config}{alpha}, 0.5, 'config echoes alpha');

# flat baseline + spike: EWMA behaves like rolling (var 0 -> sd_eff 1)
$series = mk_series((50) x 40, 200, 55, 48);
$res = LogHawk::Anomaly->new(method => 'ewma')->detect($series);
is(scalar @{ $res->{points} }, 1, 'ewma flags spike out of flat baseline');
is($res->{points}[0]{value}, 200, 'ewma spike value');
is($res->{points}[0]{direction}, 'up', 'ewma spike direction');
is($res->{points}[0]{baseline_mean}, 50, 'ewma baseline mean of flat run');
is($res->{points}[0]{severity}, 'critical', 'ewma flat-baseline spike critical');

# constant series stays quiet
$res = LogHawk::Anomaly->new(method => 'ewma')->detect(mk_series((50) x 45));
is(scalar @{ $res->{points} }, 0, 'ewma quiet on constant series');
is($res->{risk}, 0, 'ewma risk zero on constant series');

# alpha=1 makes the baseline the previous bucket: a smooth ramp never
# trips, but the final jump does.
my @ramp = map { $_ * 10 } 1 .. 40;   # 10, 20, ..., 400
$res = LogHawk::Anomaly->new(method => 'ewma', alpha => 1, min_history => 3)
    ->detect(mk_series(@ramp, 800));
is(scalar @{ $res->{points} }, 1, 'ewma alpha=1 ignores the ramp but catches the jump');
is($res->{points}[0]{value}, 800, 'ewma ramp-jump value');

# step ramp 50,50,...,65,80,95: rolling flags every rising edge,
# high-alpha ewma adapts after the first step.
$series = mk_series((50) x 40, 65, 80, 95);
my $roll_pts = LogHawk::Anomaly->new->detect($series)->{points};
my $ewma_pts = LogHawk::Anomaly->new(method => 'ewma', alpha => 0.8)->detect($series)->{points};
is(scalar @$roll_pts, 3, 'rolling flags all three step edges');
is(scalar @$ewma_pts, 1, 'ewma (alpha 0.8) adapts after the first step');

done_testing();
