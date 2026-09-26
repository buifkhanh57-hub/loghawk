package LogHawk::Series;

use strict;
use utf8;    # block-character sparkline literals are multi-byte UTF-8
use warnings;
use Carp qw(croak);
use Exporter qw(import);
use LogHawk::Util qw(
    epoch_to_label mean stddev human_size human_num min_of max_of
);

our $VERSION = '1.0.0';
our @EXPORT_OK = qw(bucketize unit_seconds ascii_chart sparkline resample);

my %UNIT_SECONDS = (
    second => 1,
    minute => 60,
    hour   => 3600,
    day    => 86400,
);

=head1 NAME

LogHawk::Series - time bucketing and gap-filling for log records

=head1 SYNOPSIS

    use LogHawk::Series;

    my $res = LogHawk::Series::bucketize(\@records, unit => 'minute', value => 'count');
    for my $b (@{ $res->{series} }) {
        print "$b->{label}  $b->{value}\n";
    }
    print "peak: $res->{stats}{peak} at bucket $res->{stats}{peak_label}\n";

    print LogHawk::Series::ascii_chart($res->{series}), "\n";
    print LogHawk::Series::sparkline([ map { $_->{value} } @{ $res->{series} } ]), "\n";

=head1 DESCRIPTION

Turns an unordered bag of parsed records into a dense, ordered time
series. Every bucket always carries all three metrics (request count,
bandwidth, error count) so downstream consumers can re-point the
"primary value" without recomputation. Empty buckets are filled with
zeros across the full [min, max] span so charts and the anomaly
detector see an honest timeline instead of a ragged one.

=cut

=head2 unit_seconds($unit)

Maps C<second|minute|hour|day> (or a raw positive integer) to a bucket
width in seconds. C<croak>s on anything else.

=cut

sub unit_seconds {
    my ($unit) = @_;
    croak('missing series unit') unless defined $unit && length $unit;
    return $UNIT_SECONDS{$unit} if $UNIT_SECONDS{$unit};
    if ($unit =~ /^\d+$/ && $unit > 0) {
        return $unit + 0;
    }
    croak("unknown series unit '$unit' (want second|minute|hour|day|<seconds>)");
}

=head2 bucketize(\@records, %options)

Options:

    unit    second|minute|hour|day|<integer seconds>   (default minute)
    value   count|bytes|errors                         (default count)
    fill    1/0 gap filling                            (default 1)
    since   epoch lower clamp for the filled range     (optional)
    until   epoch upper clamp for the filled range     (optional)

Returns:

    { unit, seconds, value, series => [ {epoch,label,value,count,bytes,errors} ],
      stats => { total, buckets, min, max, mean, sd, peak, peak_label, peak_epoch } }

C<croak>s when gap filling would produce more than 200,000 buckets
(typically a unit typo like C<--unit second> over a multi-month log).

=cut

sub bucketize {
    my ($records, %opt) = @_;
    my $unit  = exists $opt{unit}  ? $opt{unit}  : 'minute';
    my $value = exists $opt{value} ? $opt{value} : 'count';
    my $fill  = exists $opt{fill}  ? $opt{fill}  : 1;
    croak("invalid value mode '$value' (want count|bytes|errors)")
        unless $value =~ /^(count|bytes|errors)$/;
    my $sec = unit_seconds($unit);

    my ($min_b, $max_b);
    my @timed;
    for my $r (@$records) {
        next unless defined $r->{ts};
        my $b = int($r->{ts} / $sec) * $sec;
        push @timed, [ $b, $r ];
        $min_b = $b if !defined $min_b || $b < $min_b;
        $max_b = $b if !defined $max_b || $b > $max_b;
    }

    my $empty = {
        unit    => $unit,
        seconds => $sec,
        value   => $value,
        series  => [],
        stats   => { total => 0, buckets => 0, min => 0, max => 0, mean => 0,
                     sd => 0, peak => 0, peak_label => undef, peak_epoch => undef },
    };
    return $empty unless @timed;

    if ($fill) {
        $min_b = int($opt{since} / $sec) * $sec if defined $opt{since} && $opt{since} < $min_b;
        $max_b = int($opt{until} / $sec) * $sec if defined $opt{until} && $opt{until} > $max_b;
    }
    my $n_buckets = int(($max_b - $min_b) / $sec) + 1;
    croak("gap filling would produce $n_buckets buckets; raise the unit or use --no-fill")
        if $fill && $n_buckets > 200_000;

    my %acc;
    for my $pair (@timed) {
        my ($b, $r) = @$pair;
        my $a = ($acc{$b} ||= { epoch => $b, count => 0, bytes => 0, errors => 0 });
        $a->{count}++;
        $a->{bytes} += $r->{bytes} || 0;
        $a->{errors}++ if _is_error($r);
    }

    my @series;
    if ($fill) {
        for (my $e = $min_b; $e <= $max_b; $e += $sec) {
            push @series, _mk_bucket($acc{$e}, $e, $unit, $value);
        }
    }
    else {
        for my $e (sort { $a <=> $b } keys %acc) {
            push @series, _mk_bucket($acc{$e}, $e, $unit, $value);
        }
    }

    my @vals = map { $_->{value} } @series;
    my ($peak_v, $peak_i) = (0, -1);
    for my $i (0 .. $#vals) {
        if ($vals[$i] > $peak_v) {
            $peak_v = $vals[$i];
            $peak_i = $i;
        }
    }
    my %stats = (
        total      => scalar @timed,
        buckets    => scalar @series,
        min        => min_of(\@vals) // 0,
        max        => max_of(\@vals) // 0,
        mean       => mean(\@vals),
        sd         => stddev(\@vals),
        peak       => $peak_v,
        peak_epoch => $peak_i >= 0 ? $series[$peak_i]{epoch} : undef,
        peak_label => $peak_i >= 0 ? $series[$peak_i]{label} : undef,
    );
    return {
        unit    => $unit,
        seconds => $sec,
        value   => $value,
        series  => \@series,
        stats   => \%stats,
    };
}

sub _mk_bucket {
    my ($acc, $epoch, $unit, $value) = @_;
    $acc = { count => 0, bytes => 0, errors => 0 } unless $acc;
    return {
        epoch  => $epoch,
        label  => epoch_to_label($epoch, $unit),
        count  => $acc->{count},
        bytes  => $acc->{bytes},
        errors => $acc->{errors},
        value  =>
            $value eq 'count'  ? $acc->{count}  :
            $value eq 'bytes'  ? $acc->{bytes}  :
                                 $acc->{errors},
    };
}

sub _is_error {
    my ($r) = @_;
    return 1 if defined $r->{status} && $r->{status} >= 400;
    my $l = $r->{level};
    return 1 if defined $l && $l =~ /^(error|critical|alert|emergency)$/;
    return 0;
}

=head2 sparkline(\@values, [$width])

Unicode block-character sparkline. When C<$width> is given and smaller
than the series, values are downsampled by striding (max per window).

=cut

my @SPARK_BLOCKS = (' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█');

sub sparkline {
    my ($vals, $width) = @_;
    return '' unless $vals && @$vals;
    my @v = @$vals;
    if (defined $width && $width >= 1 && @v > $width) {
        my @down;
        my $step = @v / $width;
        for my $i (0 .. $width - 1) {
            my $from = int($i * $step);
            my $to   = int(($i + 1) * $step) - 1;
            $to = $#v if $to > $#v;
            my $m = $v[$from];
            for my $j ($from .. $to) { $m = $v[$j] if $v[$j] > $m; }
            push @down, $m;
        }
        @v = @down;
    }
    my $max = max_of(\@v) || 1;
    my $min = min_of(\@v) // 0;
    my $span = $max - $min;
    my $out = '';
    for my $x (@v) {
        my $t = $span > 0 ? ($x - $min) / $span : 0;
        $out .= $SPARK_BLOCKS[ int($t * 8 + 0.5) ];
    }
    return $out;
}

=head2 ascii_chart(\@buckets, %options)

Renders a horizontal-bar chart of bucket series for terminals:

    2025-11-18 03:40  ████████████████████████████████████████  412

Options: C<rows> (max rows, default 48; over-long series are downsampled
by summing), C<bar_width> (default 42), C<value> (label formatter:
C<human> formats bytes, otherwise numbers are comma-grouped).

Returns the multi-line chart as a string.

=cut

sub ascii_chart {
    my ($buckets, %opt) = @_;
    return '' unless $buckets && @$buckets;
    my $rows      = exists $opt{rows}      ? $opt{rows}      : 48;
    my $bar_width = exists $opt{bar_width} ? $opt{bar_width} : 42;
    my $fmt_human = ($opt{value} // '') eq 'bytes';

    my @b = @$buckets;
    if (@b > $rows) {
        my @down;
        my $step = @b / $rows;
        for my $i (0 .. $rows - 1) {
            my $from = int($i * $step);
            my $to   = int(($i + 1) * $step) - 1;
            $to = $#b if $to > $#b;
            my %merged = (
                epoch  => $b[$from]{epoch},
                label  => $b[$from]{label},
                count  => 0, bytes => 0, errors => 0, value => 0,
            );
            for my $j ($from .. $to) {
                $merged{count}  += $b[$j]{count}  // 0;
                $merged{bytes}  += $b[$j]{bytes}  // 0;
                $merged{errors} += $b[$j]{errors} // 0;
                $merged{value}  += $b[$j]{value}  // 0;
            }
            push @down, \%merged;
        }
        @b = @down;
    }

    my $max = 0;
    for (@b) { $max = $_->{value} if $_->{value} > $max; }
    $max ||= 1;

    my @lines;
    my $label_w = 0;
    for (@b) {
        my $l = length $_->{label};
        $label_w = $l if $l > $label_w;
    }
    for my $bucket (@b) {
        my $len = int($bucket->{value} / $max * $bar_width + 0.5);
        $len = 1 if $bucket->{value} > 0 && $len < 1;
        my $bar = '#' x $len;
        my $val = $fmt_human ? human_size($bucket->{value}) : human_num($bucket->{value});
        push @lines, sprintf("%-*s  %-*s  %8s",
            $label_w, $bucket->{label}, $bar_width, $bar, $val);
    }
    return join("\n", @lines);
}

=head2 resample(\@buckets, $new_seconds)

Re-buckets an existing dense series onto a coarser grid by summation
(e.g. minute series -> hour series). Returns plain bucket hashrefs.

=cut

sub resample {
    my ($buckets, $new_seconds) = @_;
    croak('resample needs a positive bucket width') unless $new_seconds && $new_seconds > 0;
    my %acc;
    for my $b (@$buckets) {
        my $e = int($b->{epoch} / $new_seconds) * $new_seconds;
        my $a = ($acc{$e} ||= { epoch => $e, count => 0, bytes => 0, errors => 0, value => 0 });
        $a->{count}  += $b->{count}  // 0;
        $a->{bytes}  += $b->{bytes}  // 0;
        $a->{errors} += $b->{errors} // 0;
        $a->{value}  += $b->{value}  // 0;
    }
    return [ map { $acc{$_} } sort { $a <=> $b } keys %acc ];
}

1;

__END__

=head1 DESIGN NOTES

Bucket keys are computed with integer division against UTC epochs,
which is stable across DST transitions (UTC has none) and matches how
nginx/Apache write their C<%d/%b/%Y> day stamps. Gap filling exists
because z-score anomaly detection is only meaningful when the baseline
window contains the true zeros - a spike that simply "skipped" empty
minutes would otherwise hide.

=head1 AUTHOR

Bui Bao Khanh

=head1 SEE ALSO

L<loghawk>, L<LogHawk::Anomaly>, L<LogHawk::Report>

=cut
