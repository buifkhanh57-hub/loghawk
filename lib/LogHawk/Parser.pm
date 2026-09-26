package LogHawk::Parser;

use strict;
use warnings;
use Carp qw(croak carp);
use JSON::PP ();
use LogHawk::Util qw(
    parse_combined_time parse_syslog_time parse_iso_time
    epoch_to_iso normalize_level trim
);

our $VERSION = '1.0.0';

# JSON decoder: input lines are raw UTF-8 bytes coming from log files.
my $JSON = JSON::PP->new->utf8(1);

# ---------------------------------------------------------------------------
# Line grammars
# ---------------------------------------------------------------------------

# Apache/nginx "combined" and "common" formats. The referer and user-agent
# groups are optional so one regex covers both; presence of a UA decides
# whether the record is typed 'combined' or 'common'. Optional trailing
# fields (e.g. mod_log_config %D latency) are captured as $extra.
my $RE_COMBINED = qr/^
    (\S+)\s+                       # 1: remote host or IP
    (\S+)\s+                       # 2: identd
    (\S+)\s+                       # 3: authenticated user
    \[([^\]]+)\]\s+                # 4: request time
    "([^"]*)"\s+                   # 5: request line
    (\d{3}|-)\s+                   # 6: status
    (\d+|-)                        # 7: bytes sent
    (?:\s+"([^"]*)")?              # 8: referer
    (?:\s+"([^"]*)")?              # 9: user agent
    (?:\s+(.*))?                   # 10: extra fields (e.g. %D)
$/x;

# Apache error log: [Mon Nov 18 03:07:12 2025] [error] [client 1.2.3.4] message
my $RE_ERROR = qr/^\[([^\]]+)\]\s+\[([^\]]+)\]\s+(?:\[client\s+([^\]]+)\]\s+)?(.*)$/;

# RFC 3164 (BSD) syslog, optional <PRI>:  Nov 18 03:07:12 host prog[pid]: msg
my $RE_SYSLOG = qr/^(?:<(\d{1,3})>)?\s*
    ([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+   # timestamp
    ([^\s]+)\s+                                                # hostname
    ([^:\s\[]+)(?:\[(\d+)\])?:\s*                              # program[pid]:
    (.*)$                                                      # message
/x;

# RFC 5424-ish syslog with ISO timestamp:  2025-11-18T03:07:12.123Z host prog[pid]: msg
my $RE_SYSLOG_ISO = qr/^(?:<(\d{1,3})>)?\s*
    (\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+
    ([^\s]+)\s+
    ([^:\s\[]+)(?:\[(\d+)\])?:?\s*
    (.*)$
/x;

my @SYSLOG_SEVERITIES = qw(emergency alert critical error warning notice info debug);
my @SYSLOG_FACILITIES = qw(
    kernel user mail daemon auth syslog lpr news uucp clock authpriv ftp
    ntp audit alert clock2 local0 local1 local2 local3 local4 local5 local6 local7
);

# ---------------------------------------------------------------------------
# JSON-lines field mapping
# ---------------------------------------------------------------------------

my @JSON_TS_KEYS      = ('@timestamp', 'timestamp', 'datetime', 'time', 'ts', 'date');
my @JSON_EPOCH_KEYS   = ('timestamp_ms', 'ts_ms', 'ts_epoch', 'unix_time', 'epoch');
my @JSON_MSG_KEYS     = ('msg', 'message', 'event', 'text');
my @JSON_IP_KEYS      = ('client_ip', 'remote_addr', 'client', 'src_ip', 'src', 'ip');
my @JSON_URL_KEYS     = ('url', 'request', 'uri', 'endpoint', 'target', 'path');
my @JSON_STATUS_KEYS  = ('status_code', 'resp_status', 'response_status', 'status', 'code');
my @JSON_BYTES_KEYS   = ('body_bytes_sent', 'content_length', 'size', 'bytes');
my @JSON_UA_KEYS      = ('user_agent', 'agent', 'ua');
my @JSON_METHOD_KEYS  = ('http_method', 'verb', 'method');
my @JSON_USER_KEYS    = ('auth_user', 'username', 'user');
my @JSON_DUR_MS_KEYS  = ('duration_ms', 'dur_ms', 'elapsed_ms');
my @JSON_DUR_S_KEYS   = ('request_time', 'latency', 'duration', 'elapsed', 'dur');
my @JSON_LEVEL_KEYS   = ('severity', 'lvl', 'level');

=head1 NAME

LogHawk::Parser - normalize Apache/nginx combined, syslog and JSON-lines
logs into a single record structure

=head1 SYNOPSIS

    use LogHawk::Parser;

    my $p = LogHawk::Parser->new(default_year => 2025);
    my $rec = $p->parse_line('1.2.3.4 - - [18/Nov/2025:03:07:12 +0000] "GET / HTTP/1.1" 200 512 "-" "curl/8.4.0"');
    print $rec->{ip}, ' ', $rec->{url}, ' ', $rec->{status};

    $p->parse_file('/var/log/nginx/access.log', sub {
        my ($rec) = @_;
        handle($rec) if $rec;
    });
    print "parsed ", $p->stats->{parsed}, " of ", $p->stats->{lines}, " lines\n";

=head1 DESCRIPTION

Format detection happens per line, so a single stream may mix formats
(a nginx access log piped through C<tee> plus JSON application logs, for
example). The parser is intentionally tolerant: malformed lines never
abort a run. They are counted in C<stats->{skipped}> and the first
C<error_samples> offending lines are kept for inspection.

Every record is a plain hashref with these fields (all optional except
C<type> and C<raw>):

    type      combined | common | error | syslog | json
    ts        epoch seconds (UTC), undef if the line carries no time
    ts_iso    normalized "YYYY-MM-DDTHH:MM:SSZ" rendering of ts
    line_no   1-based line number in the (concatenated) input
    ip ident user method url path proto status bytes referer ua duration_ms
    host program pid facility level message
    data      hashref of unmapped JSON fields
    raw       the original line (unless keep_raw => 0)

=cut

=head1 METHODS

=head2 new(%options)

Options:

=over 4

=item default_year => $year

Year to assume for year-less timestamps (BSD syslog, Apache error log).
When omitted, the current year is used with a one-day slack heuristic
so December logs read in January are attributed to the previous year.

=item keep_raw => 0|1

Store the original line in each record. Default: on.

=item error_samples => $n

How many malformed lines to keep for diagnostics. Default: 20.

=back

=cut

sub new {
    my ($class, %opt) = @_;
    my $self = {
        default_year  => $opt{default_year},
        keep_raw      => exists $opt{keep_raw}   ? $opt{keep_raw}   : 1,
        error_samples => exists $opt{error_samples} ? $opt{error_samples} : 20,
        stats         => {
            lines    => 0,
            blank    => 0,
            parsed   => 0,
            skipped  => 0,
            by_type  => {},
            errors   => [],
        },
    };
    return bless $self, $class;
}

=head2 stats

Returns the live counter hashref:

    { lines, blank, parsed, skipped, by_type => {combined => n, ...},
      errors => [ { line_no, text }, ... ] }

=cut

sub stats { return $_[0]->{stats} }
sub parsed { return $_[0]->{stats}{parsed} }
sub skipped { return $_[0]->{stats}{skipped} }

=head2 detect_type($line)

Classifies a line without building a full record. Returns one of
C<json>, C<combined>, C<common>, C<error>, C<syslog>, C<unknown>.

=cut

sub detect_type {
    my ($self, $line) = @_;
    return 'unknown' unless defined $line;
    my $l = $line;
    $l =~ s/\r?\n?\z//;
    return 'unknown' if $l =~ /^\s*$/;
    return 'json'    if $l =~ /^\s*\{/;
    if ($l =~ $RE_COMBINED) {
        return defined $9 ? 'combined' : 'common';
    }
    return 'error'  if $l =~ $RE_ERROR;
    return 'syslog' if $l =~ $RE_SYSLOG_ISO || $l =~ $RE_SYSLOG;
    return 'unknown';
}

=head2 parse_line($line)

Parses one line (trailing newline optional). Returns a record hashref,
or undef when the line is blank or unrecognized. Blank lines and parse
failures are reflected in C<< $self->stats >>.

=cut

sub parse_line {
    my ($self, $line) = @_;
    my $st = $self->{stats};
    return undef unless defined $line;
    $st->{lines}++;
    $line =~ s/\r?\n\z//;
    if ($line =~ /^\s*$/) {
        $st->{blank}++;
        return undef;
    }

    my $rec;
    if ($line =~ /^\s*\{/) {
        $rec = $self->_parse_json($line);
    }
    elsif ($line =~ $RE_COMBINED) {
        $rec = $self->_parse_combined($line, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10);
    }
    elsif ($line =~ $RE_ERROR) {
        $rec = $self->_parse_error($line, $1, $2, $3, $4);
    }
    elsif ($line =~ $RE_SYSLOG_ISO) {
        $rec = $self->_parse_syslog_iso($line, $1, $2, $3, $4, $5, $6);
    }
    elsif ($line =~ $RE_SYSLOG) {
        $rec = $self->_parse_syslog($line, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10);
    }

    unless (defined $rec) {
        $st->{skipped}++;
        my $n = scalar @{ $st->{errors} };
        if ($n < $self->{error_samples}) {
            push @{ $st->{errors} }, {
                line_no => $st->{lines},
                text    => substr($line, 0, 160),
            };
        }
        return undef;
    }

    $rec->{line_no} = $st->{lines};
    $rec->{raw} = $line if $self->{keep_raw};
    $st->{parsed}++;
    $st->{by_type}{ $rec->{type} }++;
    $rec->{ts_iso} = epoch_to_iso($rec->{ts}) if defined $rec->{ts};
    return $rec;
}

=head2 parse_fh($fh, [$callback])

Reads every line of an already-open filehandle, invoking C<$callback> with
each successfully parsed record. Returns the parser (chainable).

=cut

sub parse_fh {
    my ($self, $fh, $cb) = @_;
    croak('parse_fh needs an open filehandle') unless ref($fh) && ref($fh) =~ /GLOB|IO/;
    while (defined(my $line = <$fh>)) {
        my $rec = $self->parse_line($line);
        $cb->($rec) if $cb;
    }
    return $self;
}

=head2 parse_file($path, [$callback])

Opens C<$path> (C<croak> on failure) and delegates to L</parse_fh>.

=cut

sub parse_file {
    my ($self, $path, $cb) = @_;
    croak("cannot read log file '$path': $!") unless open(my $fh, '<', $path);
    eval { $self->parse_fh($fh, $cb) };
    my $err = $@;
    close $fh;
    croak($err) if $err;
    return $self;
}

=head2 parse_files(\@paths, [$callback])

Convenience wrapper over L</parse_file>; a single parser instance is
reused so counters aggregate across files.

=cut

sub parse_files {
    my ($self, $paths, $cb) = @_;
    for my $path (@$paths) {
        $self->parse_file($path, $cb);
    }
    return $self;
}

# ---------------------------------------------------------------------------
# Format parsers
# ---------------------------------------------------------------------------

sub _parse_combined {
    my ($self, $raw, $host, $ident, $user, $time_str, $request, $status, $bytes,
        $referer, $ua, $extra) = @_;

    my $rec = {
        type    => defined $ua ? 'combined' : 'common',
        ip      => $host,
        ident   => $ident,
        user    => $user,
        referer => $referer,
        ua      => $ua,
    };
    $rec->{ident}   = undef if defined $ident   && $ident   eq '-';
    $rec->{user}    = undef if defined $user    && $user    eq '-';
    $rec->{referer} = undef if defined $referer && $referer eq '-';
    $rec->{ua}      = undef if defined $ua      && $ua      eq '-';

    $rec->{ts} = parse_combined_time($time_str);
    unless (defined $rec->{ts}) {
        carp "LogHawk::Parser: unparsable CLF timestamp '$time_str' at line $self->{stats}{lines}";
        $rec->{ts} = undef;
    }

    $self->_apply_request($rec, $request);

    $rec->{status} = defined $status && $status =~ /^\d{3}$/ ? $status + 0 : undef;
    $rec->{bytes}  = defined $bytes && $bytes =~ /^\d+$/ ? $bytes + 0 : 0;
    if (defined $extra && $extra =~ /^\s*(\d+)\s*$/) {
        $rec->{duration_ms} = $1 + 0;    # e.g. nginx $request_time in microseconds or %D
    }
    return $self->_finish($rec);
}

sub _apply_request {
    my ($self, $rec, $request) = @_;
    $request = trim($request // '');
    if ($request =~ /^([A-Za-z]+)\s+(\S+)(?:\s+(\S+))?$/) {
        $rec->{method} = uc $1;
        $rec->{url}    = $2;
        $rec->{proto}  = defined $3 ? $3 : undef;
    }
    else {
        # Binary garbage / HTTP/0.9 / "-" requests: keep verbatim as URL.
        $rec->{method} = undef;
        $rec->{url}    = $request ne '' ? $request : undef;
        $rec->{proto}  = undef;
    }
    if (defined $rec->{url}) {
        my $p = $rec->{url};
        $p =~ s/[?#].*$//;
        $rec->{path} = $p;
    }
    else {
        $rec->{path} = undef;
    }
    return $rec;
}

sub _parse_error {
    my ($self, $raw, $time_str, $level_raw, $client, $message) = @_;
    my $rec = { type => 'error' };
    if ($time_str =~ /^(\w{3})\s+(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})$/) {
        my $mo = LogHawk::Util::month_num($2);
        $rec->{ts} = defined $mo
            ? LogHawk::Util::ymd_epoch($7 + 0, $mo, $3 + 0, $4 + 0, $5 + 0, $6 + 0, 0)
            : undef;
    }
    else {
        $rec->{ts} = undef;
    }
    $rec->{level}   = normalize_level($level_raw) // 'error';
    $rec->{ip}      = defined $client ? $client : undef;
    $rec->{message} = $message;
    return $self->_finish($rec);
}

sub _parse_syslog {
    my ($self, $raw, $pri, $mon, $day, $h, $mi, $s, $host, $program, $pid, $msg) = @_;
    my $rec = { type => 'syslog' };
    $rec->{ts} = parse_syslog_time("$mon $day $h:$mi:$s", time(), $self->{default_year});
    $self->_apply_syslog($rec, $pri, $host, $program, $pid, $msg);
    return $self->_finish($rec);
}

sub _parse_syslog_iso {
    my ($self, $raw, $pri, $time_str, $host, $program, $pid, $msg) = @_;
    my $rec = { type => 'syslog' };
    $rec->{ts} = parse_iso_time($time_str);
    $self->_apply_syslog($rec, $pri, $host, $program, $pid, $msg);
    return $self->_finish($rec);
}

sub _apply_syslog {
    my ($self, $rec, $pri, $host, $program, $pid, $msg) = @_;
    if (defined $pri && $pri =~ /^\d{1,3}$/ && $pri < 192) {
        my $sev = $pri % 8;
        my $fac = $pri >> 3;
        $rec->{facility} = $SYSLOG_FACILITIES[$fac] if $fac < @SYSLOG_FACILITIES;
        $rec->{level}    = $SYSLOG_SEVERITIES[$sev];
        $rec->{pri}      = $pri + 0;
    }
    else {
        $rec->{level} = _infer_level($msg);
    }
    $rec->{host}    = $host;
    $rec->{program} = $program;
    $rec->{pid}     = defined $pid ? $pid + 0 : undef;
    $rec->{message} = $msg;
    # Extract a leading IPv4 from the message (firewall/dropbear style lines).
    if (!defined $rec->{ip} && $msg =~ /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/) {
        $rec->{ip} = $1;
    }
    return $rec;
}

sub _infer_level {
    my ($msg) = @_;
    return 'critical' if $msg =~ /\b(critical|crit|fatal|panic)\b/i;
    return 'error'    if $msg =~ /\b(error|err|fail(ed|ure)?|denied|refused|timed? ?out)\b/i;
    return 'warning'  if $msg =~ /\b(warn(ing)?|deprecated|retry)\b/i;
    return 'notice'   if $msg =~ /\bnotice\b/i;
    return 'debug'    if $msg =~ /\bdebug\b/i;
    return 'info';
}

sub _first_key {
    my ($data, $keys) = @_;
    for my $k (@$keys) {
        return ($k, $data->{$k}) if exists $data->{$k} && defined $data->{$k};
    }
    return (undef, undef);
}

sub _epoch_from_value {
    my ($v) = @_;
    return undef unless defined $v;
    if ($v =~ /^\d{10}$/)                  { return $v + 0; }
    if ($v =~ /^\d{13}$/)                  { return int($v / 1000); }
    if ($v =~ /^\d{10}\.\d+$/)             { return $v + 0; }
    my $e = parse_iso_time($v);
    return $e if defined $e;
    return undef;
}

sub _parse_json {
    my ($self, $line) = @_;
    my $data = eval { $JSON->decode($line) };
    if (!$data || $@ || ref($data) ne 'HASH') {
        return undef;
    }

    my $rec = { type => 'json', data => {} };

    my ($k, $v);
    ($k, $v) = _first_key($data, \@JSON_EPOCH_KEYS);
    $rec->{ts} = defined $v ? _epoch_from_value($v) : undef;
    if (!defined $rec->{ts}) {
        ($k, $v) = _first_key($data, \@JSON_TS_KEYS);
        if (defined $v) {
            $rec->{ts} = $v =~ /^\d+$/ ? _epoch_from_value($v) : parse_iso_time($v);
        }
    }

    ($k, $v) = _first_key($data, \@JSON_MSG_KEYS);
    $rec->{message} = $v;
    ($k, $v) = _first_key($data, \@JSON_IP_KEYS);
    $rec->{ip} = $v;
    ($k, $v) = _first_key($data, \@JSON_URL_KEYS);
    if (defined $v) {
        $rec->{url} = $v;
        my $p = $v;
        $p =~ s/[?#].*$//;
        $rec->{path} = $p;
    }
    ($k, $v) = _first_key($data, \@JSON_METHOD_KEYS);
    $rec->{method} = defined $v ? uc $v : undef;
    ($k, $v) = _first_key($data, \@JSON_STATUS_KEYS);
    $rec->{status} = defined $v && $v =~ /^\d{3}$/ ? $v + 0 : undef;
    ($k, $v) = _first_key($data, \@JSON_BYTES_KEYS);
    $rec->{bytes} = defined $v && $v =~ /^\d+$/ ? $v + 0 : 0;
    ($k, $v) = _first_key($data, \@JSON_UA_KEYS);
    $rec->{ua} = $v;
    ($k, $v) = _first_key($data, \@JSON_USER_KEYS);
    $rec->{user} = $v;
    $rec->{host} = exists $data->{host} && defined $data->{host} ? $data->{host} : undef;
    ($k, $v) = _first_key($data, \@JSON_DUR_MS_KEYS);
    $rec->{duration_ms} = defined $v && $v =~ /^\d+(\.\d+)?$/ ? int($v) : undef;
    if (!defined $rec->{duration_ms}) {
        ($k, $v) = _first_key($data, \@JSON_DUR_S_KEYS);
        if (defined $v && $v =~ /^\d+(\.\d+)?$/) {
            my $n = $v + 0;
            $rec->{duration_ms} = $n < 1000 ? int($n * 1000) : int($n);
        }
    }
    ($k, $v) = _first_key($data, \@JSON_LEVEL_KEYS);
    $rec->{level} = defined $v ? (normalize_level($v) // 'info') : _infer_level($rec->{message} // '');

    my %mapped = map { $_ => 1 }
        (@JSON_TS_KEYS, @JSON_EPOCH_KEYS, @JSON_MSG_KEYS, @JSON_IP_KEYS,
         @JSON_URL_KEYS, @JSON_STATUS_KEYS, @JSON_BYTES_KEYS, @JSON_UA_KEYS,
         @JSON_METHOD_KEYS, @JSON_USER_KEYS, @JSON_DUR_MS_KEYS, @JSON_DUR_S_KEYS,
         @JSON_LEVEL_KEYS, 'host');
    for my $dk (keys %$data) {
        next if $mapped{$dk};
        $rec->{data}{$dk} = $data->{$dk};
    }
    delete $rec->{data} unless %{ $rec->{data} };

    return $self->_finish($rec);
}

# Shared normalization for every record type.
sub _finish {
    my ($self, $rec) = @_;
    $rec->{status} = undef unless defined $rec->{status} && $rec->{status} =~ /^\d{3}$/;
    $rec->{bytes}  = 0     unless defined $rec->{bytes}  && $rec->{bytes}  =~ /^\d+$/;
    if (exists $rec->{duration_ms}) {
        $rec->{duration_ms} = undef unless defined $rec->{duration_ms} && $rec->{duration_ms} =~ /^\d+(\.\d+)?$/;
        $rec->{duration_ms} += 0 if defined $rec->{duration_ms};
    }
    for my $opt (qw(user ident referer ua)) {
        $rec->{$opt} = undef if exists $rec->{$opt} && !defined $rec->{$opt};
    }
    return $rec;
}

1;

__END__

=head1 TOLERANCE AND COUNTERS

Log files in the wild are dirty: rotated mid-write, truncated, polluted
by binary probes. LogHawk never dies on unexpected input. Every line is
accounted for:

    lines   = blank + parsed + skipped

Unparsable lines are counted and (up to C<error_samples>) retained with
their line number so the C<parse> subcommand can print a diagnostic
report. Malformed CLF timestamps still produce a record (with C<ts>
undef) but trigger a C<carp> warning unless warnings are disabled.

=head1 SUPPORTED FORMATS

=over 4

=item * Apache/nginx combined: C<1.2.3.4 - - [18/Nov/2025:03:07:12 +0000] "GET / HTTP/1.1" 200 512 "http://ref" "UA-string">

=item * Apache/nginx common: same without referer/UA fields

=item * Apache error log: C<[Mon Nov 18 03:07:12 2025] [error] [client 1.2.3.4] message>

=item * BSD syslog (RFC 3164), with or without C<< <PRI> >>: C<Nov 18 03:07:12 web01 sshd[2318]: Failed password ...>

=item * ISO/RFC 5424-style syslog: C<2025-11-18T03:07:12.100Z web01 nginx: 10.0.0.1 GET ...>

=item * JSON lines: field names are auto-mapped (C<@timestamp>, C<remote_addr>, C<status_code>, ...), unknown keys are preserved under C<< $rec->{data} >>

=back

=head1 AUTHOR

Bui Bao Khanh

=head1 SEE ALSO

L<loghawk>, L<LogHawk::Filters>, L<LogHawk::Stats>, L<LogHawk::Util>

=cut
