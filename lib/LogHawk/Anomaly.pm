package LogHawk::Anomaly;

use strict;
use warnings;
use LogHawk::Util qw(mean stddev clamp);

our $VERSION = '1.0.0';

=head1 NAME

LogHawk::Anomaly - rolling z-score spike and dip detection

=head1 SYNOPSIS

    use LogHawk::Anomaly;

    my $det = LogHawk::Anomaly->new(sensitivity => 'medium', mode => 'spikes');
    my $res = $det->detect($series);   # from LogHawk::Series::bucketize

    # EWMA baseline: reacts faster to slow level shifts than a flat window
    my $ewma = LogHawk::Anomaly->new(method => 'ewma', alpha => 0.3);
    my $res2 = $ewma->detect($series);

    for my $p (@{ $res->{points} }) {
        printf "%s  value=%d  baseline=%.1f  z=%.2f  severity=%s\n",
            $p->{label}, $p->{value}, $p->{baseline_mean}, $p->{zscore}, $p->{severity};
    }
    print "risk score: $res->{risk}\n";

=head1 DESCRIPTION

Classic traffic spike detection without any heavyweight statistics
dependency. For each bucket C<i>, the previous C<window> buckets form
the baseline; if the baseline has at least C<min_history> points, the
z-score of the current value is

    z = (value - baseline_mean) / max(baseline_sd, epsilon)

A bucket is flagged when z crosses the threshold in the configured
direction (C<spikes> up, C<dips> down, C<both>). When the baseline is
perfectly flat (sd = 0) the effective sd of 1 keeps the score sane:
any meaningful deviation from a flat baseline is caught, and a constant
series never trips a false alarm.

Contiguous flagged buckets are merged into "events" so one sustained
incident does not read as fifty separate alerts.

Two baseline I<methods> are available:

=over 4

=item * C<rolling> (default) - the flat window of the previous
C<window> buckets described above.

=item * C<ewma> - an exponentially weighted moving average baseline.
Instead of a flat window, a running mean C<mu> and variance C<var> are
maintained and updated after every bucket with smoothing factor
C<alpha>:

    d   = v - mu
    mu  = mu + alpha * d
    var = (1 - alpha) * var + alpha * d * d

The z-score of each bucket is computed against the mu/var state built
from all I<prior> buckets (the current bucket never contributes to its
own baseline). Small C<alpha> values remember long stretches of
history and ignore slow drifts; large values track the traffic closely
and only sudden jumps are flagged. EWMA is the better choice when
traffic has a strong trend or daily ramp, where a flat rolling window
over-polls every rising edge.

=back

=cut

my %SENSITIVITY = (
    low    => 4.0,
    medium => 3.0,
    high   => 2.0,
);

=head2 sensitivity_threshold($name)

Maps C<low|medium|high> to z-thresholds 4.0 / 3.0 / 2.0. Unknown names
C<croak> via the constructor validation.

=cut

sub sensitivity_threshold {
    my ($name) = @_;
    return $SENSITIVITY{ $name // 'medium' };
}

=head2 new(%options)

    window        baseline length in buckets          (default 30)
    threshold     z-score cut-off                     (default 3.0)
    sensitivity   low|medium|high shortcut            (optional)
    min_history   minimum baseline points required    (default 10)
    mode          spikes|dips|both                    (default spikes)
    method        rolling|ewma baseline               (default rolling)
    alpha         EWMA smoothing factor 0<a<=1        (default 0.3)

Giving both C<threshold> and C<sensitivity> prefers the explicit
threshold. C<method> and C<alpha> are independent of the direction
C<mode>: both baselines feed the same z-score cut-off.

=cut

sub new {
    my ($class, %opt) = @_;
    my $threshold;
    if (defined $opt{threshold}) {
        $threshold = $opt{threshold} + 0;
        die "LogHawk::Anomaly: threshold must be positive\n" unless $threshold > 0;
    }
    else {
        my $sens = $opt{sensitivity} // 'medium';
        die "LogHawk::Anomaly: unknown sensitivity '$sens' (want low|medium|high)\n"
            unless exists $SENSITIVITY{$sens};
        $threshold = $SENSITIVITY{$sens};
    }
    my $self = {
        window      => $opt{window} // 30,
        threshold   => $threshold,
        min_history => $opt{min_history} // 10,
        mode        => $opt{mode} // 'spikes',
        method      => $opt{method} // 'rolling',
        alpha       => defined $opt{alpha} ? $opt{alpha} + 0 : 0.3,
    };
    die "LogHawk::Anomaly: unknown mode '$self->{mode}' (want spikes|dips|both)\n"
        unless $self->{mode} =~ /^(spikes|dips|both)$/;
    die "LogHawk::Anomaly: unknown method '$self->{method}' (want rolling|ewma)\n"
        unless $self->{method} =~ /^(rolling|ewma)$/;
    die "LogHawk::Anomaly: alpha must be > 0 and <= 1\n"
        unless $self->{alpha} > 0 && $self->{alpha} <= 1;
    die "LogHawk::Anomaly: window must be >= 2\n" unless $self->{window} >= 2;
    return bless $self, $class;
}

=head2 detect(\@buckets)

Input: the dense bucket array produced by L<LogHawk::Series/bucketize>
(any array of hashrefs with C<value>, C<label>, C<epoch> works).

Returns:

    {
        points => [ { epoch, label, value, baseline_mean, baseline_sd,
                      zscore, severity, direction } ],
        events => [ { start_epoch, end_epoch, start_label, end_label,
                      buckets, peak_value, peak_z, severity } ],
        risk   => max |z| seen (0.0 when nothing flagged),
        config => { window, threshold, min_history, mode, method, alpha },
    }

Severity from |z|: >= 6 critical, >= 4.5 high, >= 3.5 medium, else low.

=cut

sub detect {
    my ($self, $buckets) = @_;
    my ($W, $T, $MH, $mode) = @{ $self }{qw(window threshold min_history mode)};

    my @points;
    my $max_abs_z = 0;
    my @flagged_idx;

    my $ewma = $self->{method} eq 'ewma';
    my ($mu, $var) = (undef, 0);

    for my $i (0 .. $#$buckets) {
        my $v = $buckets->[$i]{value} + 0;

        my ($m, $sd);
        if ($ewma) {
            # mu/var summarize buckets 0 .. i-1; never the current one.
            if (defined $mu) {
                $m  = $mu;
                $sd = sqrt($var);
            }
            # advance the state with the current bucket for later baselines
            $mu = defined $mu ? $mu + $self->{alpha} * ($v - $mu) : $v;
            if (defined $m) {
                my $d = $v - $m;
                $var = (1 - $self->{alpha}) * $var + $self->{alpha} * $d * $d;
            }
            next if $i < $MH;
        }
        else {
            my $lo = $i - $W;
            $lo = 0 if $lo < 0;
            next if $i - $lo < $MH;
            my @base = map { $_->{value} + 0 } @{ $buckets }[ $lo .. $i - 1 ];
            $m  = mean(\@base);
            $sd = stddev(\@base);
        }

        my $sd_eff = $sd > 0 ? $sd : 1;
        my $z = ($v - $m) / $sd_eff;

        my $hit = 0;
        my $dir;
        if ($z >= $T && ($mode eq 'spikes' || $mode eq 'both')) {
            $hit = 1;
            $dir = 'up';
        }
        elsif ($z <= -$T && ($mode eq 'dips' || $mode eq 'both')) {
            $hit = 1;
            $dir = 'down';
        }
        $max_abs_z = abs($z) if abs($z) > $max_abs_z;
        next unless $hit;

        push @points, {
            epoch         => $buckets->[$i]{epoch},
            label         => $buckets->[$i]{label},
            value         => $v,
            baseline_mean => sprintf('%.2f', $m) + 0,
            baseline_sd   => sprintf('%.2f', $sd) + 0,
            zscore        => sprintf('%.2f', $z) + 0,
            severity      => _severity(abs($z)),
            direction     => $dir,
        };
        push @flagged_idx, $i;
    }

    return {
        points => \@points,
        events => $self->_merge_events(\@flagged_idx, $buckets, \@points),
        risk   => sprintf('%.2f', $max_abs_z) + 0,
        config => {
            window      => $W,
            threshold   => $T,
            min_history => $MH,
            mode        => $mode,
            method      => $self->{method},
            alpha       => $self->{alpha},
        },
    };
}

sub _severity {
    my ($az) = @_;
    return 'critical' if $az >= 6.0;
    return 'high'     if $az >= 4.5;
    return 'medium'   if $az >= 3.5;
    return 'low';
}

# Group consecutive flagged buckets into single events.
sub _merge_events {
    my ($self, $idxs, $buckets, $points) = @_;
    return [] unless @$idxs;

    my @events;
    my @runs = ( [ shift @$idxs ] );
    for my $i (@$idxs) {
        if ($i == $runs[-1][-1] + 1) {
            push @{ $runs[-1] }, $i;
        }
        else {
            push @runs, [$i];
        }
    }
    my $pt = 0;
    for my $run (@runs) {
        my @run_points = @$points[ $pt .. $pt + $#$run ];
        $pt += scalar @$run;
        my ($peak_v, $peak_z) = (0, 0);
        for my $p (@run_points) {
            $peak_v = $p->{value} if $p->{value} > $peak_v;
            $peak_z = $p->{zscore} if abs($p->{zscore}) > abs($peak_z);
        }
        push @events, {
            start_epoch => $buckets->[ $run->[0] ]{epoch},
            end_epoch   => $buckets->[ $run->[-1] ]{epoch},
            start_label => $buckets->[ $run->[0] ]{label},
            end_label   => $buckets->[ $run->[-1] ]{label},
            buckets     => scalar @$run,
            peak_value  => $peak_v,
            peak_z      => sprintf('%.2f', $peak_z) + 0,
            severity    => _severity(abs($peak_z)),
        };
    }
    return \@events;
}

=head2 describe_point($point)

One-line human summary of a flagged bucket, used by the C<spikes> and
C<tailf> commands. Callable as a method (C<< LogHawk::Anomaly->describe_point($p) >>)
or as a plain function (C<LogHawk::Anomaly::describe_point($p)>):

    2025-11-18 03:41:00  value 412 vs baseline 9.6 (z=7.31, up, critical)

=cut

sub describe_point {
    my $p = @_ > 1 ? $_[1] : $_[0];   # works as method or plain function
    return sprintf('%s  value %d vs baseline %.2f (z=%.2f, %s, %s)',
        $p->{label}, $p->{value}, $p->{baseline_mean}, $p->{zscore},
        $p->{direction} // '?', $p->{severity});
}

=head2 describe_event($event)

One-line human summary of a merged event.

=cut

sub describe_event {
    my $e = @_ > 1 ? $_[1] : $_[0];   # works as method or plain function
    my $span = $e->{start_label} // '?';
    $span .= ' .. ' . $e->{end_label} if defined $e->{end_label} && $e->{end_label} ne $span;
    return sprintf('%s  %d bucket(s), peak %d (z=%.2f, %s)',
        $span, $e->{buckets}, $e->{peak_value}, $e->{peak_z}, $e->{severity});
}

=head2 risk_score(\@buckets)

Shorthand for C<< detect(...)->{risk} >> when only the single number
matters (exit-code plumbing in CI pipelines).

=cut

sub risk_score {
    my ($self, $buckets) = @_;
    my $res = $self->detect($buckets);
    return $res->{risk};
}

1;

__END__

=head1 WHY ROLLING Z-SCORES

Exponentially-weighted schemes react faster but also fire on benign
retry storms; a plain rolling window over the immediately preceding
buckets is transparent: every alert can be reproduced by hand from the
printed baseline (mean and sd) - which matters when you are deciding
whether to wake someone up. The window is intentionally exclusive of
the current bucket, so a long sustained spike gradually stops alerting
once it *is* the baseline; pair LogHawk with a pager that cares about
transitions, not states.

When trend-following is wanted instead, setting C<method> to C<ewma>
keeps the same transparent z-score language while letting the baseline
glide with the traffic; tune C<alpha> down (0.05-0.15) for stable
traffic and up (0.3-0.6) for bursty endpoints.

=head1 AUTHOR

Bui Bao Khanh

=head1 SEE ALSO

L<loghawk>, L<LogHawk::Series>, L<LogHawk::Tail>

=cut
