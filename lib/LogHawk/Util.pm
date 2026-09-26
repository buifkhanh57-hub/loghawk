package LogHawk::Util;

use strict;
use warnings;
use Exporter qw(import);
use POSIX qw(strftime);
use Time::Piece ();
use Carp qw(croak carp);

our $VERSION = '1.0.0';
our @EXPORT_OK = qw(
    human_size human_num pct truncate_str trim now
    status_class normalize_level
    month_num days_from_civil ymd_epoch utc_offset_to_seconds
    parse_combined_time parse_syslog_time parse_iso_time parse_datetime
    epoch_to_iso epoch_to_label
    mean stddev median percentile
    compile_re min_of max_of clamp
);
our %EXPORT_TAGS = (
    all  => \@EXPORT_OK,
    time => [qw(month_num days_from_civil ymd_epoch utc_offset_to_seconds
                parse_combined_time parse_syslog_time parse_iso_time parse_datetime
                epoch_to_iso epoch_to_label)],
    math => [qw(mean stddev median percentile min_of max_of clamp)],
);

# ---------------------------------------------------------------------------
# Human-readable formatting
# ---------------------------------------------------------------------------

=head1 NAME

LogHawk::Util - shared helpers: sizes, numbers, time parsing, math

=head1 SYNOPSIS

    use LogHawk::Util qw(human_size parse_datetime epoch_to_iso mean stddev);

    print human_size(15360);              # 15.0 KB
    my $epoch = parse_datetime('-1h');    # one hour ago
    print epoch_to_iso($epoch);           # 2025-11-18T03:07:12Z
    my $sd = stddev([2, 4, 4, 4, 5, 5, 7, 9]);

=head1 DESCRIPTION

Small, dependency-free helpers shared by every other LogHawk module.
Time handling is done with explicit UTC arithmetic (the days-from-civil
algorithm) so results never depend on the local timezone of the host,
while C<Time::Piece>/C<POSIX::strftime> are used for formatting.

=cut

sub human_size {
    my ($bytes) = @_;
    return '0 B' unless defined $bytes;
    $bytes += 0;
    my $sign = $bytes < 0 ? '-' : '';
    $bytes = abs($bytes);
    my @units = qw(B KB MB GB TB PB);
    my $u = 0;
    while ($bytes >= 1024 && $u < $#units) {
        $bytes /= 1024;
        $u++;
    }
    my $num = $u == 0 ? sprintf('%d', $bytes) : sprintf('%.1f', $bytes);
    return $sign . $num . ' ' . $units[$u];
}

sub human_num {
    my ($n) = @_;
    return '0' unless defined $n;
    my $neg = $n < 0 ? '-' : '';
    my $int = int(abs($n) + 0.5);
    my $s = reverse $int;
    $s =~ s/(\d{3})(?=\d)/$1,/g;
    return $neg . scalar reverse $s;
}

sub pct {
    my ($part, $total, $digits) = @_;
    $digits = 1 unless defined $digits;
    return sprintf('%.' . $digits . 'f', 0) unless $total;
    return sprintf('%.' . $digits . 'f', 100 * $part / $total);
}

sub truncate_str {
    my ($s, $max) = @_;
    return '' unless defined $s;
    return $s if length($s) <= $max;
    return substr($s, 0, $max - 1) . '~' if $max >= 1;
    return '';
}

sub trim {
    my ($s) = @_;
    return '' unless defined $s;
    $s =~ s/^\s+//;
    $s =~ s/\s+$//;
    return $s;
}

sub now { return time() }

# ---------------------------------------------------------------------------
# HTTP status helpers
# ---------------------------------------------------------------------------

sub status_class {
    my ($status) = @_;
    return 'unknown' unless defined $status && $status =~ /^\d{3}$/;
    my $c = int($status / 100);
    return "${c}xx" if $c >= 1 && $c <= 5;
    return 'unknown';
}

my %KNOWN_LEVELS = map { $_ => 1 } qw(
    debug info notice warning error critical alert emergency
);

sub normalize_level {
    my ($level) = @_;
    return undef unless defined $level;
    $level = lc trim($level);
    return undef if $level eq '';
    return 'error'     if $level eq 'err';
    return 'critical'  if $level =~ /^(crit|fatal)$/;
    return 'emergency' if $level =~ /^(emerg|panic)$/;
    return 'warning'   if $level eq 'warn';
    return 'debug'     if $level eq 'trace';
    return 'notice'    if $level eq 'notif';
    return $level if $KNOWN_LEVELS{$level};
    return undef;
}

# ---------------------------------------------------------------------------
# Calendar / time arithmetic (UTC only, no local timezone surprises)
# ---------------------------------------------------------------------------

my %MONTH_NUM = (
    jan => 1, feb => 2, mar => 3, apr => 4, may => 5, jun => 6,
    jul => 7, aug => 8, sep => 9, oct => 10, nov => 11, dec => 12,
);

sub month_num {
    my ($name) = @_;
    return undef unless defined $name;
    return $MONTH_NUM{lc substr($name, 0, 3)};
}

=head2 days_from_civil($year, $month, $day)

Returns the number of days between 1970-01-01 and the given proleptic
Gregorian date (Howard Hinnant's algorithm). Pure integer math: no
timezone, no DST, no locale. Used as the basis for every epoch
calculation in LogHawk.

=cut

sub days_from_civil {
    my ($y, $m, $d) = @_;
    $y -= $m <= 2;
    my $era = int(($y >= 0 ? $y : $y - 399) / 400);
    my $yoe = $y - $era * 400;
    my $mp  = $m + ($m > 2 ? -3 : 9);
    my $doy = int((153 * $mp + 2) / 5) + $d - 1;
    my $doe = $yoe * 365 + int($yoe / 4) - int($yoe / 100) + $doy;
    return $era * 146097 + $doe - 719468;
}

sub ymd_epoch {
    my ($y, $mo, $d, $h, $mi, $s, $offset) = @_;
    $offset = 0 unless defined $offset;
    my $days = days_from_civil($y, $mo, $d);
    return $days * 86400 + $h * 3600 + $mi * 60 + $s - $offset;
}

# 'Z', '+07:00', '-0530', '+00' -> seconds east of UTC
sub utc_offset_to_seconds {
    my ($off) = @_;
    return 0 unless defined $off;
    $off = trim($off);
    return 0 if $off eq '' || $off =~ /^[Zz]$/;
    if ($off =~ /^([+-])(\d{2}):?(\d{2})?$/) {
        my $sign = $1 eq '-' ? -1 : 1;
        my $h = $2 + 0;
        my $m = defined $3 ? $3 + 0 : 0;
        return $sign * ($h * 3600 + $m * 60);
    }
    carp "LogHawk::Util: unrecognized UTC offset '$off', assuming +0000";
    return 0;
}

# Apache/nginx CLF time: 18/Nov/2025:03:07:12 +0000
sub parse_combined_time {
    my ($str) = @_;
    return undef unless defined $str;
    my ($d, $mon, $y, $h, $mi, $s, $off) =
        $str =~ m{^(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?$};
    return undef unless defined $d;
    my $mo = month_num($mon);
    return undef unless defined $mo;
    my $offset = defined $off ? utc_offset_to_seconds($off) : 0;
    return ymd_epoch($y + 0, $mo, $d + 0, $h + 0, $mi + 0, $s + 0, $offset);
}

# BSD syslog time: "Nov 18 03:07:12" (year-less). Heuristic: choose the
# year that keeps the timestamp at or before now+1 day.
sub parse_syslog_time {
    my ($str, $now, $default_year) = @_;
    return undef unless defined $str;
    $now = time() unless defined $now;
    my ($mon, $d, $h, $mi, $s) =
        $str =~ m{^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$};
    return undef unless defined $mon;
    my $mo = month_num($mon);
    return undef unless defined $mo;
    my $year;
    if (defined $default_year) {
        $year = $default_year;
    }
    else {
        my @lt = gmtime($now);
        $year = $lt[5] + 1900;
        my $probe = ymd_epoch($year, $mo, $d + 0, $h + 0, $mi + 0, $s + 0, 0);
        $year-- if defined $probe && $probe > $now + 86400;
    }
    return ymd_epoch($year, $mo, $d + 0, $h + 0, $mi + 0, $s + 0, 0);
}

# ISO 8601: 2025-11-18T03:07:12(.5)?(Z|+07:00|+0700)?
sub parse_iso_time {
    my ($str) = @_;
    return undef unless defined $str;
    my ($y, $mo, $d, $h, $mi, $s, $off) =
        $str =~ m{^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|z|[+-]\d{2}:?\d{2})?$};
    return undef unless defined $y;
    my $offset = defined $off ? utc_offset_to_seconds($off) : 0;
    return ymd_epoch($y + 0, $mo + 0, $d + 0, $h + 0, $mi + 0, $s + 0, $offset);
}

=head2 parse_datetime($string, [$now_epoch])

Flexible time parser used by C<--since>/C<--until> options. Understands:

    now                  current time
    -30s -5m -2h -1d -1w relative offsets
    2025-11-18           date (midnight UTC)
    2025-11-18T10:00:00Z ISO 8601 with optional fraction and zone
    2025-11-18 10:00:00  space-separated variant
    2025/11/18 10:00     slash variant
    10:00 / 10:00:30     today at HH:MM (UTC)
    18/Nov/2025:10:00:00 +0000   Apache CLF format

Returns an epoch (UTC seconds) or undef when the string is not
recognized. C<$now_epoch> defaults to C<time()> and anchors relative
and HH:MM forms.

=cut

sub parse_datetime {
    my ($str, $now) = @_;
    return undef unless defined $str;
    $now = defined $now ? $now : time();
    $str = trim($str);
    return undef if $str eq '';

    return $now if lc $str eq 'now';

    if ($str =~ /^-(\d+)([smhdw])$/i) {
        my %mult = (s => 1, m => 60, h => 3600, d => 86400, w => 604800);
        return $now - $1 * $mult{lc $2};
    }

    if ($str =~ /^(\d{4})-(\d{2})-(\d{2})$/) {
        return ymd_epoch($1 + 0, $2 + 0, $3 + 0, 0, 0, 0, 0);
    }

    my $e = parse_iso_time($str);
    return $e if defined $e;

    $e = parse_combined_time($str);
    return $e if defined $e;

    if ($str =~ m{^(\d{4})/(\d{1,2})/(\d{1,2})(?:\s+(\d{1,2}):(\d{2})(?::(\d{2}))?)?$}) {
        return ymd_epoch($1 + 0, $2 + 0, $3 + 0,
            defined $4 ? $4 + 0 : 0, defined $5 ? $5 + 0 : 0, defined $6 ? $6 + 0 : 0, 0);
    }

    if ($str =~ /^(\d{1,2}):(\d{2})(?::(\d{2}))?$/) {
        my @lt = gmtime($now);
        return ymd_epoch($lt[5] + 1900, $lt[4] + 1, $lt[3],
            $1 + 0, $2 + 0, defined $3 ? $3 + 0 : 0, 0);
    }

    return undef;
}

sub epoch_to_iso {
    my ($epoch) = @_;
    return undef unless defined $epoch;
    return strftime('%Y-%m-%dT%H:%M:%SZ', gmtime($epoch));
}

sub epoch_to_label {
    my ($epoch, $unit) = @_;
    return undef unless defined $epoch;
    my $fmt =
        $unit eq 'second' ? '%Y-%m-%d %H:%M:%S' :
        $unit eq 'minute' ? '%Y-%m-%d %H:%M'    :
        $unit eq 'hour'   ? '%Y-%m-%d %H:00'    :
                            '%Y-%m-%d';
    return strftime($fmt, gmtime($epoch));
}

# ---------------------------------------------------------------------------
# Small statistics
# ---------------------------------------------------------------------------

sub mean {
    my ($vals) = @_;
    return 0 unless $vals && @$vals;
    my $sum = 0;
    $sum += $_ for @$vals;
    return $sum / @$vals;
}

sub stddev {
    my ($vals) = @_;
    return 0 unless $vals && @$vals;
    return 0 if @$vals < 2;
    my $m = mean($vals);
    my $ss = 0;
    $ss += ($_ - $m) * ($_ - $m) for @$vals;
    return sqrt($ss / (@$vals - 1));
}

sub median {
    my ($vals) = @_;
    return percentile($vals, 50);
}

=head2 percentile(\@values, $p)

Linear-interpolation percentile (R-7, same as Excel/numpy default).
Values need not be pre-sorted; the list is copied and sorted internally.

=cut

sub percentile {
    my ($vals, $p) = @_;
    return undef unless $vals && @$vals;
    my @s = sort { $a <=> $b } @$vals;
    my $n = @s;
    return $s[-1] if $p >= 100;
    return $s[0]  if $p <= 0;
    my $k = ($n - 1) * $p / 100;
    my $f = int($k);
    my $c = $f + 1 < $n ? $f + 1 : $f;
    my $d = $k - $f;
    return $s[$f] + ($s[$c] - $s[$f]) * $d;
}

# ---------------------------------------------------------------------------
# Regex / misc
# ---------------------------------------------------------------------------

=head2 compile_re($pattern, [$name])

Compiles a user-supplied pattern with C<qr//>, C<croak>ing with a clear
message (including the pattern name) when the regex is invalid. Used by
LogHawk::Filters so bad C<--url-regex> values fail fast.

=cut

sub compile_re {
    my ($pat, $name) = @_;
    croak('empty regex pattern' . (defined $name ? " for $name" : '')) unless defined $pat && length $pat;
    my $re = eval { qr/$pat/ };
    if (!$re || $@) {
        my $err = $@ ? $@ : 'unknown error';
        $err =~ s/\s+$//;
        croak("invalid regex" . (defined $name ? " for $name" : '') . " '$pat': $err");
    }
    return $re;
}

sub min_of {
    my ($vals) = @_;
    return undef unless $vals && @$vals;
    my $m = $vals->[0];
    for (@$vals) { $m = $_ if $_ < $m; }
    return $m;
}

sub max_of {
    my ($vals) = @_;
    return undef unless $vals && @$vals;
    my $m = $vals->[0];
    for (@$vals) { $m = $_ if $_ > $m; }
    return $m;
}

sub clamp {
    my ($v, $lo, $hi) = @_;
    return $lo if $v < $lo;
    return $hi if $v > $hi;
    return $v;
}

1;

__END__

=head1 AUTHOR

Bui Bao Khanh

=head1 SEE ALSO

L<loghawk>, L<LogHawk::Parser>, L<LogHawk::Filters>, L<LogHawk::Stats>

=cut
