package LogHawk::Export;

use strict;
use warnings;
use Carp qw(croak);
use Exporter qw(import);
use JSON::PP ();
use LogHawk::Util qw(epoch_to_iso human_size);

our $VERSION = '1.0.0';
our @EXPORT_OK = qw(csv_escape record_hash);

my $JSON_PRETTY  = JSON::PP->new->ascii(1)->canonical(1)->pretty(1);
my $JSON_COMPACT = JSON::PP->new->ascii(1)->canonical(1);

=head1 NAME

LogHawk::Export - JSON / NDJSON / CSV serialization of records and summaries

=head1 SYNOPSIS

    use LogHawk::Export;

    print LogHawk::Export::records_to_csv(\@records);
    print LogHawk::Export::records_to_json(\@records);
    LogHawk::Export::write_file('/tmp/out.json', $content);

=head1 DESCRIPTION

Output layer for the C<export> subcommand (and the C<--json> flags of
the other commands). CSV follows RFC 4180: fields containing quotes,
commas or newlines are wrapped in double quotes and embedded quotes are
doubled. JSON is emitted via L<JSON::PP> with C<canonical> key ordering
so diffs between runs stay stable.

=cut

my @CSV_FIELDS = qw(
    ts_iso type ip ident user method url status bytes referer ua
    host program pid facility level message duration_ms
);

=head2 csv_escape($value)

RFC 4180 escaping. Returns the bare value when no special characters
are present.

=cut

sub csv_escape {
    my ($v) = @_;
    return '' unless defined $v;
    $v = "$v";
    if ($v =~ /[",\r\n]/) {
        $v =~ s/"/""/g;
        $v = "\"$v\"";
    }
    return $v;
}

=head2 record_hash($record)

Strips LogHawk-internal keys (C<raw>, the UA cache) and renders C<ts>
as C<ts_iso>, producing the canonical external representation of a
record.

=cut

sub record_hash {
    my ($rec) = @_;
    my %out;
    for my $k (qw(type ts_iso line_no ip ident user method url path proto
                  status bytes referer ua duration_ms host program pid
                  pri facility level message))
    {
        $out{$k} = $rec->{$k} if exists $rec->{$k} && defined $rec->{$k};
    }
    if (exists $rec->{data} && ref $rec->{data} eq 'HASH') {
        $out{data} = $rec->{data};
    }
    return \%out;
}

=head2 records_to_json(\@records, [$pretty])

A JSON document: C<{ "meta": {count}, "records": [...] }>. C<$pretty>
defaults to on.

=cut

sub records_to_json {
    my ($records, $pretty) = @_;
    $pretty = 1 unless defined $pretty;
    my $obj = {
        meta    => { count => scalar @$records, format => 'loghawk-records/1' },
        records => [ map { record_hash($_) } @$records ],
    };
    return ($pretty ? $JSON_PRETTY : $JSON_COMPACT)->encode($obj);
}

=head2 records_to_ndjson(\@records)

One compact JSON object per line - friendlier for C<jq> and streaming
consumers.

=cut

sub records_to_ndjson {
    my ($records) = @_;
    my @lines;
    for my $rec (@$records) {
        push @lines, $JSON_COMPACT->encode(record_hash($rec));
    }
    return join('', map { "$_\n" } @lines);
}

=head2 records_to_csv(\@records, [\@fields])

RFC 4180 CSV with a header row. C<@fields> defaults to the canonical
column list; unknown names are ignored, any record key is allowed.

=cut

sub records_to_csv {
    my ($records, $fields) = @_;
    my @fields = defined $fields ? @$fields : @CSV_FIELDS;
    my @lines = join(',', map { csv_escape($_) } @fields);
    for my $rec (@$records) {
        my @row;
        for my $f (@fields) {
            my $v = $f eq 'ts_iso'
                ? (defined $rec->{ts_iso} ? $rec->{ts_iso}
                  : defined $rec->{ts} ? epoch_to_iso($rec->{ts}) : undef)
                : $rec->{$f};
            push @row, csv_escape($v);
        }
        push @lines, join(',', @row);
    }
    return join('', map { "$_\n" } @lines);
}

=head2 summary_to_json($summary, [$pretty])

Serializes a L<LogHawk::Stats/summary> structure (all keys are already
plain data).

=cut

sub summary_to_json {
    my ($summary, $pretty) = @_;
    $pretty = 1 unless defined $pretty;
    my $obj = {
        meta    => { format => 'loghawk-summary/1' },
        summary => $summary,
    };
    return ($pretty ? $JSON_PRETTY : $JSON_COMPACT)->encode($obj);
}

=head2 series_to_csv($series_result, [$value_name])

CSV rendering of a L<LogHawk::Series/bucketize> result:
C<label,epoch,value> (+ C<count,bytes,errors>).

=cut

sub series_to_csv {
    my ($res, $value_name) = @_;
    $value_name = defined $value_name ? $value_name : ($res->{value} // 'value');
    my @lines = ('label,epoch,' . csv_escape($value_name) . ',count,bytes,errors');
    for my $b (@{ $res->{series} }) {
        push @lines, join(',', map { csv_escape($_) }
            $b->{label}, $b->{epoch}, $b->{value}, $b->{count}, $b->{bytes}, $b->{errors});
    }
    return join('', map { "$_\n" } @lines);
}

=head2 parse_stats_to_json($parser, [$pretty])

Diagnostics document from a L<LogHawk::Parser> instance: line counters
plus the retained malformed-line samples.

=cut

sub parse_stats_to_json {
    my ($parser, $pretty) = @_;
    $pretty = 1 unless defined $pretty;
    my $obj = {
        meta  => { format => 'loghawk-parsestats/1' },
        stats => $parser->stats,
    };
    return ($pretty ? $JSON_PRETTY : $JSON_COMPACT)->encode($obj);
}

=head2 write_file($path, $content)

Writes C<$content> to C<$path>, creating parent directories is *not*
attempted; C<croak>s with the OS error on failure. A path of C<->
returns the content unchanged (caller prints to STDOUT).

=cut

sub write_file {
    my ($path, $content) = @_;
    return $content if $path eq '-';
    croak("cannot write '$path': $!") unless open(my $fh, '>', $path);
    print {$fh} $content;
    unless (close $fh) {
        croak("error closing '$path': $!");
    }
    return $content;
}

1;

__END__

=head1 FORMAT NOTES

=over 4

=item * CSV quoting is applied per-field at write time; reading the
output back with any RFC 4180 parser (Excel, Python csv, LOAD DATA)
round-trips cleanly, including embedded newlines inside JSON C<message>
fields.

=item * NDJSON is the recommended interchange for downstream tooling:
one record per line survives partial reads, and C<jq .status> style
pipelines work without a full-document parse.

=item * C<canonical(1)> sorts hash keys so two runs over the same log
produce byte-identical output (stable diffs, cacheable artifacts).

=back

=head1 AUTHOR

Bui Bao Khanh

=head1 SEE ALSO

L<loghawk>, L<LogHawk::Stats>, L<LogHawk::Series>

=cut
