package LogHawk;

use strict;
use warnings;

our $VERSION = '1.0.0';
our $AUTHOR  = 'Bui Bao Khanh';
our $HOMEPAGE = 'https://github.com/buifkhanh57-hub/loghawk';

=head1 NAME

LogHawk - professional log-analysis & monitoring toolkit (core Perl only)

=head1 SYNOPSIS

    use LogHawk;

    my @cmds  = LogHawk->command_names;
    my $table = LogHawk->command_table;   # aligned help listing
    print LogHawk->banner;                # version banner used by bin/loghawk

=head1 DESCRIPTION

LogHawk turns raw server logs (Apache/nginx combined, syslog, JSON
lines) into normalized records, then answers operational questions:

    loghawk stats   access.log           # who, what, how much
    loghawk filter  --status 5xx ...     # surgical record extraction
    loghawk series  --unit minute        # request timelines
    loghawk spikes  --sensitivity high   # z-score anomaly detection
    loghawk tailf   access.log           # live follow with alerting
    loghawk report  --format html        # shareable summary documents
    loghawk export  --format csv         # hand off to other tooling

The distribution runs on a plain Perl 5 (>= 5.14) install using core
modules only: L<Getopt::Long>, L<Pod::Usage>, L<POSIX>, L<File::Basename>,
L<Time::Piece>, L<JSON::PP> (plus L<Time::HiRes> for follow mode).

This top-level module is the version holder and the command registry
used by the CLI help screen; the work happens in the L<LogHawk::*> classes.

=cut

# name => [summary, argument spec]
my %COMMANDS = (
    parse  => [ 'normalize any supported log format into records', 'parse [options] [file...]' ],
    stats  => [ 'top IPs, status distribution, bandwidth, UA summary', 'stats [options] [file...]' ],
    filter => [ 'surgical record extraction (status/ip/url/time/level)', 'filter [options] [file...]' ],
    series => [ 'per second/minute/hour/day request buckets', 'series [options] [file...]' ],
    spikes => [ 'z-score anomaly detection (rolling or EWMA baseline)', 'spikes [options] [file...]' ],
    tailf  => [ 'follow a growing log with live spike alerting', 'tailf [options] file' ],
    report => [ 'text/markdown/HTML summary document', 'report [options] [file...]' ],
    export => [ 'dump records as JSON/NDJSON/CSV', 'export [options] [file...]' ],
);

=head2 command_names

Ordered list of subcommand names (insertion order of the registry).

=cut

sub command_names {
    return qw(parse stats filter series spikes tailf report export);
}

=head2 command_summary($name)

One-line description for the given subcommand, or undef.

=cut

sub command_summary {
    my ($class, $name) = @_;
    return undef unless exists $COMMANDS{$name};
    return $COMMANDS{$name}[0];
}

=head2 command_usage($name)

The C<loghawk COMMAND --help> synopsis line for the subcommand.

=cut

sub command_usage {
    my ($class, $name) = @_;
    return undef unless exists $COMMANDS{$name};
    return 'loghawk ' . $COMMANDS{$name}[1];
}

=head2 command_table

Pre-formatted, aligned "name - summary" listing for the main help.

=cut

sub command_table {
    my ($class) = @_;
    my $w = 0;
    for my $n ($class->command_names) {
        $w = length $n if length $n > $w;
    }
    my @lines;
    for my $n ($class->command_names) {
        push @lines, sprintf('  %-*s  %s', $w, $n, $COMMANDS{$n}[0]);
    }
    return join("\n", @lines);
}

=head2 banner

Single-line version banner printed by C<--version> and help screens.

=cut

sub banner {
    my ($class) = @_;
    return "loghawk $VERSION - log analysis & monitoring toolkit (by $AUTHOR)";
}

1;

__END__

=head1 MODULE MAP

    bin/loghawk              CLI entry point (dispatch, option parsing, POD)
    lib/LogHawk.pm           this module: version + command registry
    lib/LogHawk/Util.pm      sizes, numbers, UTC time math, small stats
    lib/LogHawk/Parser.pm    combined/common/error/syslog/JSON-line parsing
    lib/LogHawk/Filters.pm   composable record predicates (status, ip, time...)
    lib/LogHawk/Stats.pm     aggregations + user-agent intelligence
    lib/LogHawk/Series.pm    time bucketing, gap filling, charts
    lib/LogHawk/Anomaly.pm   rolling z-score spikes/dips
    lib/LogHawk/Tail.pm      follow mode, rotation tolerance, live alerts
    lib/LogHawk/Report.pm    text/markdown/HTML renderers
    lib/LogHawk/Export.pm    JSON/NDJSON/CSV serialization

=head1 AUTHOR

Bui Bao Khanh

=head1 LICENSE

MIT - see the LICENSE file in this distribution.

=cut
