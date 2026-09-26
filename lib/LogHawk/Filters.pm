package LogHawk::Filters;

use strict;
use warnings;
use Carp qw(croak);
use LogHawk::Util qw(
    parse_datetime compile_re normalize_level status_class trim
);

our $VERSION = '1.0.0';

=head1 NAME

LogHawk::Filters - composable record filters for the loghawk CLI

=head1 SYNOPSIS

    use LogHawk::Filters;

    my $f = LogHawk::Filters->new(
        status    => '5xx,404',
        ip        => '10.0.0.0/8,203.0.113.*',
        url_regex => '\.php$',
        since     => '-1h',
        level     => 'error',
    );

    my @kept = grep { $f->matches($_) } @records;
    print $f->to_string, "\n";   # status in [5xx,404]; ip in ...; ...

=head1 DESCRIPTION

Builds an ordered list of predicate closures from CLI options and
matches records against all of them (logical AND). Recognized options:

    status          2xx/3xx/4xx/5xx classes and/or exact codes, comma separated
    exclude_status  same syntax, records matching are dropped
    ip              exact IPs, CIDR networks (10.0.0.0/8), glob (203.0.113.*)
                    or raw regex fragments, comma separated
    url             substring match on url or path
    url_regex       perl regex against url or path
    method          GET, POST, ... (case-insensitive, comma separated)
    level           syslog-ish levels, synonyms normalized (err -> error)
    since / until   anything LogHawk::Util::parse_datetime understands
    host user referer_regex grep
    min_bytes max_bytes

Filters requiring a timestamp drop records without one (fail-closed)
so a filter chain can never silently widen its result set.

=cut

my %LEVEL_SYNONYMS = (
    err   => 'error',   crit => 'critical', emerg => 'emergency',
    fatal => 'critical', panic => 'emergency', warn => 'warning',
    trace => 'debug',
);

# ---------------------------------------------------------------------------
# IPv4 / CIDR helpers
# ---------------------------------------------------------------------------

sub ipv4_to_int {
    my ($ip) = @_;
    return undef unless defined $ip && $ip =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
    my ($a, $b, $c, $d) = ($1, $2, $3, $4);
    return undef if $a > 255 || $b > 255 || $c > 255 || $d > 255;
    return ($a << 24) | ($b << 16) | ($c << 8) | $d;
}

sub cidr_match {
    my ($ip, $spec) = @_;
    my ($net, $bits) = $spec =~ m{^(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2}))?$}
        ? ($1, defined $2 ? $2 : 32)
        : return undef;
    return undef if $bits > 32;
    my $neti = ipv4_to_int($net);
    return undef unless defined $neti;
    my $mask = $bits == 0 ? 0 : (0xFFFFFFFF << (32 - $bits)) & 0xFFFFFFFF;
    my $ipi  = ipv4_to_int($ip);
    return undef unless defined $ipi;
    return (($ipi & $mask) == ($neti & $mask)) ? 1 : 0;
}

# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------

=head1 METHODS

=head2 new(%options)

Builds the predicate list. Each option value is validated immediately;
C<croak> is called (with the option name) on malformed input such as an
invalid regex, unknown level, or impossible CIDR. This gives CLI users
fail-fast behaviour instead of silent zero-row results.

=cut

sub new {
    my ($class, %opt) = @_;
    my $self = bless { preds => [] }, $class;

    if (defined $opt{status}) {
        $self->_add_status_spec($opt{status}, 1);
    }
    if (defined $opt{exclude_status}) {
        $self->_add_status_spec($opt{exclude_status}, 0);
    }
    if (defined $opt{ip}) {
        $self->_add_ip_spec($opt{ip});
    }
    if (defined $opt{url}) {
        my $needle = $opt{url};
        $self->add("url contains '$needle'", sub {
            my $r = shift;
            return 0 unless defined $r->{url} || defined $r->{path};
            (defined $r->{url}  && index($r->{url},  $needle) >= 0)
         || (defined $r->{path} && index($r->{path}, $needle) >= 0);
        });
    }
    if (defined $opt{url_regex}) {
        my $re = compile_re($opt{url_regex}, '--url-regex');
        $self->add("url ~ $opt{url_regex}", sub {
            my $r = shift;
            (defined $r->{url}  && $r->{url}  =~ $re)
         || (defined $r->{path} && $r->{path} =~ $re);
        });
    }
    if (defined $opt{method}) {
        my %methods = map { uc trim($_) => 1 } split /,/, $opt{method};
        $self->add('method in [' . join(',', sort keys %methods) . ']', sub {
            my $r = shift;
            return defined $r->{method} && $methods{ $r->{method} };
        });
    }
    if (defined $opt{level}) {
        my %levels;
        for my $raw (split /,/, $opt{level}) {
            my $lv = trim($raw);
            $lv = $LEVEL_SYNONYMS{ lc $lv } // lc $lv;
            croak("invalid --level '$raw'") unless normalize_level($lv) || $LEVEL_SYNONYMS{ lc $raw };
            $levels{$lv} = 1;
        }
        $self->add('level in [' . join(',', sort keys %levels) . ']', sub {
            my $r = shift;
            my $l = $r->{level};
            return 0 unless defined $l;
            $l = $LEVEL_SYNONYMS{ lc $l } // lc $l;
            return $levels{$l} ? 1 : 0;
        });
    }
    if (defined $opt{since} || defined $opt{until}) {
        my ($since, $until);
        if (defined $opt{since}) {
            $since = parse_datetime($opt{since});
            croak("invalid --since '{$opt{since}}'") unless defined $since;
        }
        if (defined $opt{until}) {
            $until = parse_datetime($opt{until});
            croak("invalid --until '{$opt{until}}'") unless defined $until;
        }
        my $label = 'time in ['
            . (defined $since ? scalar(localtime($since)) : '-inf') . ', '
            . (defined $until ? scalar(localtime($until)) : '+inf') . ']';
        $self->add($label, sub {
            my $r = shift;
            return 0 unless defined $r->{ts};
            return 0 if defined $since && $r->{ts} < $since;
            return 0 if defined $until && $r->{ts} > $until;
            return 1;
        });
    }
    if (defined $opt{host}) {
        my %hosts = map { lc trim($_) => 1 } split /,/, $opt{host};
        $self->add('host in [' . join(',', sort keys %hosts) . ']', sub {
            my $r = shift;
            return defined $r->{host} && $hosts{ lc $r->{host} };
        });
    }
    if (defined $opt{user}) {
        my %users = map { trim($_) => 1 } split /,/, $opt{user};
        $self->add('user in [' . join(',', sort keys %users) . ']', sub {
            my $r = shift;
            return defined $r->{user} && $users{ $r->{user} };
        });
    }
    if (defined $opt{referer_regex}) {
        my $re = compile_re($opt{referer_regex}, '--referer-regex');
        $self->add("referer ~ $opt{referer_regex}", sub {
            my $r = shift;
            return defined $r->{referer} && $r->{referer} =~ $re;
        });
    }
    if (defined $opt{grep}) {
        my $re = compile_re($opt{grep}, '--grep');
        $self->add("raw ~ $opt{grep}", sub {
            my $r = shift;
            my $raw = defined $r->{raw} ? $r->{raw} : '';
            return $raw =~ $re;
        });
    }
    if (defined $opt{min_bytes}) {
        my $min = $opt{min_bytes};
        $self->add("bytes >= $min", sub { $_[0]{bytes} >= $min });
    }
    if (defined $opt{max_bytes}) {
        my $max = $opt{max_bytes};
        $self->add("bytes <= $max", sub { $_[0]{bytes} <= $max });
    }

    return $self;
}

sub _add {
    my ($self, $label, $code) = @_;
    push @{ $self->{preds} }, [ $label, $code ];
    return $self;
}

# status spec: "5xx", "404", "5xx,404,3xx"
sub _add_status_spec {
    my ($self, $spec, $keep) = @_;
    my (@classes, %codes);
    for my $part (split /,/, $spec) {
        my $p = trim($part);
        croak("invalid status filter '$p'") if $p eq '';
        if ($p =~ /^([1-5])xx$/i) {
            push @classes, $1;
        }
        elsif ($p =~ /^\d{3}$/) {
            $codes{$p} = 1;
        }
        else {
            croak("invalid status filter '$p' (want NNN or Nxx)");
        }
    }
    my $desc = ($keep ? 'status in [' : 'status not in [')
        . join(',', @classes ? (map { "${_}xx" } sort @classes) : (), sort keys %codes) . ']';
    $self->add($desc, sub {
        my $r = shift;
        my $st = $r->{status};
        return 0 unless defined $st;
        my $hit = $codes{$st} ? 1 : 0;
        unless ($hit) {
            my $c = int($st / 100);
            $hit = 1 if grep { $_ == $c } @classes;
        }
        return $keep ? $hit : !$hit;
    });
    return $self;
}

# ip spec: mix of exact / CIDR / glob / regex fragments
sub _add_ip_spec {
    my ($self, $spec) = @_;
    my (@cidrs, %exact, @regexes, @globs);
    for my $part (split /,/, $spec) {
        my $p = trim($part);
        croak("invalid --ip filter '$p'") if $p eq '';
        if ($p =~ m{^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$}) {
            croak("invalid CIDR network '$p'") unless defined ipv4_to_int($1) && $2 <= 32;
            push @cidrs, $p;
        }
        elsif ($p =~ /^\d{1,3}(?:\.\d{1,3}){3}$/) {
            croak("invalid IP literal '$p'") unless defined ipv4_to_int($p);
            $exact{$p} = 1;
        }
        elsif ($p =~ /[\*\?]/) {
            my $re = quotemeta($p);
            $re =~ s/\\\*/[^ ]*/g;
            $re =~ s/\\\?/./g;
            push @globs, qr/^$re$/;
        }
        else {
            push @regexes, compile_re($p, '--ip');
        }
    }
    my $desc = 'ip in [' . $spec . ']';
    $self->add($desc, sub {
        my $r = shift;
        my $ip = $r->{ip};
        return 0 unless defined $ip && length $ip;
        return 1 if $exact{$ip};
        for my $c (@cidrs)   { return 1 if cidr_match($ip, $c); }
        for my $g (@globs)   { return 1 if $ip =~ $g; }
        for my $re (@regexes) { return 1 if $ip =~ $re; }
        return 0;
    });
    return $self;
}

=head2 matches($record)

True when the record satisfies every predicate. An empty filter (no
options given) matches everything.

=cut

sub matches {
    my ($self, $rec) = @_;
    return 1 unless @{ $self->{preds} };
    for my $p (@{ $self->{preds} }) {
        return 0 unless $p->[1]->($rec);
    }
    return 1;
}

=head2 count(\@records)

Number of records matched (convenience for stats output).

=cut

sub count {
    my ($self, $records) = @_;
    my $n = 0;
    for my $r (@$records) {
        $n++ if $self->matches($r);
    }
    return $n;
}

=head2 add($label, $coderef)

Appends a custom predicate; used internally and available for library
consumers who need domain-specific matching.

=head2 describe

Returns the list of human-readable predicate labels.

=head2 to_string

C<describe> joined with "; ", or "none" for an empty filter.

=head2 any(@filters)

Class method returning a filter object that matches when ANY of the
given filters matches (logical OR across chains).

=cut

sub add { goto &_add }

sub describe {
    my ($self) = @_;
    return map { $_->[0] } @{ $self->{preds} };
}

sub to_string {
    my ($self) = @_;
    my @d = $self->describe;
    return @d ? join('; ', @d) : 'none';
}

sub any {
    my ($class, @filters) = @_;
    my $self = bless { preds => [] }, $class;
    my @f = grep { $_ } @filters;
    return $self unless @f;
    my $desc = join(' OR ', map { '(' . $_->to_string . ')' } @f);
    $self->add($desc, sub {
        my $r = shift;
        for my $f (@f) {
            return 1 if $f->matches($r);
        }
        return 0;
    });
    return $self;
}

1;

__END__

=head1 DESIGN NOTES

Predicates are plain closures stored as C<< [label, coderef] >> pairs,
which keeps matching cheap (one sub call per predicate, no object
dispatch) and makes the filter fully serializable by inspection via
L</describe>. Time comparisons are fail-closed: a record without a
usable timestamp can never satisfy a C<--since>/C<--until> chain, which
prevents "unknown" records from leaking into time-bounded reports.

=head1 AUTHOR

Bui Bao Khanh

=head1 SEE ALSO

L<loghawk>, L<LogHawk::Parser>, L<LogHawk::Util>

=cut
