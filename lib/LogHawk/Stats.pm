package LogHawk::Stats;

use strict;
use warnings;
use LogHawk::Util qw(
    human_size human_num status_class epoch_to_iso epoch_to_label
    mean stddev percentile pct max_of
);

our $VERSION = '1.0.0';

=head1 NAME

LogHawk::Stats - streaming aggregations and user-agent intelligence

=head1 SYNOPSIS

    use LogHawk::Stats;

    my $s = LogHawk::Stats->new;
    $s->add($_) for @records;
    my $summary = $s->summary(top => 10);
    print human_size($summary->{overview}{bytes_total}), " transferred\n";
    print "$_->[0]: $_->[1]\n" for @{ $summary->{top_ips} };

    # one-shot convenience
    my $sum2 = LogHawk::Stats->analyze(\@records)->summary;

=head1 DESCRIPTION

A single pass over the records updates all counters at once: status-code
distribution, top client IPs, top URLs, bandwidth by calendar day,
hour-of-day histogram, per-minute request counts (for peak detection),
response durations (global percentiles, per-path latency profiles and
the slowest individual requests) and user-agent classification.

Top-N lists are computed with a bounded insertion buffer instead of a
full sort: for the typical C<--top 10> request over hundreds of
thousands of distinct keys this is O(N * top) with tiny constants and
never materializes a sorted copy of the key space.

=cut

# ---------------------------------------------------------------------------
# User-agent intelligence
# ---------------------------------------------------------------------------

# Order matters: more specific patterns first (Edge/Opera carry Chrome
# tokens; bots identify themselves before generic family detection).
my @BROWSER_RULES = (
    [ qr/YandexBot\/?([\d.]*)/i,          'YandexBot' ],
    [ qr/Googlebot\/?([\d.]*)/i,          'Googlebot' ],
    [ qr/bingbot\/?([\d.]*)/i,            'Bingbot' ],
    [ qr/DuckDuckBot\/?([\d.]*)/i,        'DuckDuckBot' ],
    [ qr/Baiduspider\/?([\d.]*)/i,        'Baiduspider' ],
    [ qr/AhrefsBot\/?([\d.]*)/i,          'AhrefsBot' ],
    [ qr/SemrushBot\/?([\d.]*)/i,         'SemrushBot' ],
    [ qr/facebookexternalhit(?:\/([\d.]+))?/i, 'Facebook' ],
    [ qr/Twitterbot\/?([\d.]*)/i,         'Twitterbot' ],
    [ qr/Slackbot(?:-LinkExpanding)?\/?([\d.]*)/i, 'Slackbot' ],
    [ qr/LinkedInBot\/?([\d.]*)/i,        'LinkedInBot' ],
    [ qr/(?:Bot|Spider|Crawler|Scrapy)/i, 'Other Bot' ],
    [ qr/Edg(?:e|A|iOS)?\/([\d.]+)/,      'Edge' ],
    [ qr/OPR\/([\d.]+)/,                  'Opera' ],
    [ qr/Opera[\s\/]([\d.]+)/,            'Opera' ],
    [ qr/Chrome\/([\d.]+)/,               'Chrome' ],
    [ qr/Chromium\/([\d.]+)/,             'Chromium' ],
    [ qr/Firefox\/([\d.]+)/,              'Firefox' ],
    [ qr/Trident\/.*rv:([\d.]+)/,         'Internet Explorer' ],
    [ qr/MSIE\s+([\d.]+)/,                'Internet Explorer' ],
    [ qr/Version\/([\d.]+).*Safari/,      'Safari' ],
    [ qr/Safari\/[\d.]+/,                 'Safari' ],
    [ qr/curl\/([\d.]+)/,                 'curl' ],
    [ qr/Wget\/([\d.]+)/,                 'Wget' ],
    [ qr/python-requests\/([\d.]+)/,      'python-requests' ],
    [ qr/python-urllib\/?([\d.]*)/,       'python-urllib' ],
    [ qr/Go-http-client\/([\d.]+)/,       'Go HTTP Client' ],
    [ qr/Java\/([\d.]+)/,                 'Java' ],
    [ qr/Apache-HttpClient\/([\d.]+)/,    'Java HttpClient' ],
    [ qr/libwww-perl\/([\d.]+)/,          'libwww-perl' ],
    [ qr/LWP::UserAgent/,                 'libwww-perl' ],
    [ qr/node|axios|undici/i,             'Node.js' ],
);

my @OS_RULES = (
    [ qr/Windows NT 10\.0/,  'Windows',       '10/11' ],
    [ qr/Windows NT 6\.3/,   'Windows',       '8.1' ],
    [ qr/Windows NT 6\.2/,   'Windows',       '8' ],
    [ qr/Windows NT 6\.1/,   'Windows',       '7' ],
    [ qr/Windows NT 6\.0/,   'Windows',       'Vista' ],
    [ qr/Windows NT 5\.[12]/,'Windows',       'XP/2003' ],
    [ qr/Windows Phone/,     'Windows Phone', '' ],
    [ qr/Windows 98/,        'Windows',       '98' ],
    [ qr/Windows/,           'Windows',       '' ],
    [ qr/iPhone/,            'iOS',           'iPhone' ],
    [ qr/iPad/,              'iOS',           'iPad' ],
    [ qr/iPod/,              'iOS',           'iPod' ],
    [ qr/Android[\s\/](\d+(?:\.\d+)*)/, 'Android', undef ],
    [ qr/Android/,           'Android',       '' ],
    [ qr/Mac OS X[ _]([\d_]+)/, 'macOS',      undef ],
    [ qr/Macintosh|Mac_PowerPC/, 'macOS',     '' ],
    [ qr/Ubuntu/,            'Linux',         'Ubuntu' ],
    [ qr/Debian/,            'Linux',         'Debian' ],
    [ qr/Fedora/,            'Linux',         'Fedora' ],
    [ qr/CentOS/,            'Linux',         'CentOS' ],
    [ qr/FreeBSD/,           'FreeBSD',       '' ],
    [ qr/OpenBSD/,           'OpenBSD',       '' ],
    [ qr/Linux/i,            'Linux',         '' ],
    [ qr/curl|Wget|python|Go-http|Java|libwww|Node\.js/i, 'Other', 'CLI/library' ],
);

my %BOT_BROWSER_NAMES = map { $_ => 1 } (
    'YandexBot', 'Googlebot', 'Bingbot', 'DuckDuckBot', 'Baiduspider',
    'AhrefsBot', 'SemrushBot', 'Facebook', 'Twitterbot', 'Slackbot',
    'LinkedInBot', 'Other Bot',
);
my %TOOL_BROWSER_NAMES = map { $_ => 1 } (
    'curl', 'Wget', 'python-requests', 'python-urllib', 'Go HTTP Client',
    'Java', 'Java HttpClient', 'libwww-perl', 'Node.js',
);

=head2 parse_ua($user_agent)

Static method classifying a User-Agent string. Returns a hashref:

    { browser => 'Chrome', version => '120.0.0.0',
      os      => 'Windows', os_version => '10/11',
      device  => 'Desktop',            # Desktop | Mobile | Tablet | Bot | Other
      kind    => 'browser' }           # browser | bot | tool

Unknown or empty UA strings yield browser 'Unknown', os 'Unknown'.

=cut

sub parse_ua {
    my ($ua) = @_;
    $ua = '' unless defined $ua;
    my %out = (
        browser    => 'Unknown',
        version    => '',
        os         => 'Unknown',
        os_version => '',
        device     => 'Other',
        kind       => 'browser',
    );
    return \%out if $ua eq '' || $ua eq '-';

    for my $rule (@BROWSER_RULES) {
        if ($ua =~ $rule->[0]) {
            $out{browser} = $rule->[1];
            $out{version} = defined $1 ? $1 : '';
            last;
        }
    }
    for my $rule (@OS_RULES) {
        if ($ua =~ $rule->[0]) {
            $out{os} = $rule->[1];
            if (defined $rule->[2]) {
                $out{os_version} = $rule->[2];
            }
            elsif (defined $1) {
                (my $v = $1) =~ s/_/./g;
                $out{os_version} = $v;
            }
            last;
        }
    }
    my $b = $out{browser};
    if ($BOT_BROWSER_NAMES{$b} || $b eq 'Other Bot') {
        $out{kind}   = 'bot';
        $out{device} = 'Bot';
    }
    elsif ($TOOL_BROWSER_NAMES{$b}) {
        $out{kind}   = 'tool';
        $out{device} = 'Other';
    }
    elsif ($ua =~ /iPad|iPod/) {
        $out{device} = 'Tablet';
    }
    elsif ($ua =~ /iPhone|Android(?!.*(?:Tablet|SM-T))/ || $ua =~ /Mobile Safari/) {
        $out{device} = 'Mobile';
    }
    elsif ($out{os} eq 'Android') {
        $out{device} = 'Tablet';
    }
    else {
        $out{device} = 'Desktop';
    }
    return \%out;
}

# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

=head2 new

Creates an empty aggregator.

=head2 add($record)

Updates all counters with one parsed record (records without C<ts> are
still counted for totals; time-based buckets simply skip them).

=head2 analyze(\@records)

Class-level convenience: C<new>, C<add> for each record, returns the
aggregator itself.

=cut

sub new {
    my ($class) = @_;
    my $self = bless {
        total          => 0,
        types          => {},
        status_codes   => {},
        status_classes => {},
        ips            => {},
        ips_bytes      => {},
        urls           => {},
        urls_bytes     => {},
        methods        => {},
        referers       => {},
        uas            => {},
        browsers       => {},
        oses           => {},
        devices        => {},
        ua_kinds       => {},
        hosts          => {},
        users          => {},
        programs       => {},
        levels         => {},
        facilities     => {},
        bytes_total    => 0,
        bytes_max      => 0,
        requests_by_day  => {},
        bytes_by_day     => {},
        minute_counts    => {},
        hour_counts      => {},
        first_ts         => undef,
        last_ts          => undef,
        durations        => [],
        dur_by_path      => {},
        path_dur_count   => {},
        slowest          => [],
        error_count      => 0,
    }, $class;
    return $self;
}

sub analyze {
    my ($class, $records) = @_;
    my $s = $class->new;
    $s->add($_) for @$records;
    return $s;
}

sub _is_error {
    my ($rec) = @_;
    return 1 if defined $rec->{status} && $rec->{status} >= 400;
    my $l = $rec->{level};
    return 1 if defined $l && $l =~ /^(error|critical|alert|emergency)$/;
    return 0;
}

sub add {
    my ($self, $rec) = @_;
    $self->{total}++;
    $self->{types}{ $rec->{type} }++ if defined $rec->{type};

    if (defined $rec->{status}) {
        $self->{status_codes}{ $rec->{status} }++;
        my $cls = status_class($rec->{status});
        $self->{status_classes}{$cls}++ unless $cls eq 'unknown';
    }
    if (_is_error($rec)) {
        $self->{error_count}++;
    }

    my $bytes = $rec->{bytes} || 0;
    $self->{bytes_total} += $bytes;
    $self->{bytes_max} = $bytes if $bytes > $self->{bytes_max};

    if (defined $rec->{ip} && length $rec->{ip}) {
        $self->{ips}{ $rec->{ip} }++;
        $self->{ips_bytes}{ $rec->{ip} } += $bytes;
    }
    if (defined $rec->{path} && length $rec->{path}) {
        $self->{urls}{ $rec->{path} }++;
        $self->{urls_bytes}{ $rec->{path} } += $bytes;
    }
    $self->{methods}{ $rec->{method} }++ if defined $rec->{method};
    if (defined $rec->{referer} && length $rec->{referer}) {
        $self->{referers}{ $rec->{referer} }++;
    }
    if (defined $rec->{ua} && length $rec->{ua}) {
        my $info = $rec->{_ua} ||= parse_ua($rec->{ua});   # classify once per record
        $self->{uas}{ $rec->{ua} }++;
        $self->{browsers}{ $info->{browser} }++;
        $self->{oses}{ $info->{os} }++;
        $self->{devices}{ $info->{device} }++;
        $self->{ua_kinds}{ $info->{kind} }++;
    }
    $self->{hosts}{ $rec->{host} }++    if defined $rec->{host}    && length $rec->{host};
    $self->{users}{ $rec->{user} }++    if defined $rec->{user}    && length $rec->{user};
    $self->{programs}{ $rec->{program} }++ if defined $rec->{program} && length $rec->{program};
    $self->{levels}{ $rec->{level} }++  if defined $rec->{level}   && length $rec->{level};
    $self->{facilities}{ $rec->{facility} }++ if defined $rec->{facility};

    if (defined $rec->{duration_ms}) {
        push @{ $self->{durations} }, $rec->{duration_ms};
        my $path = defined $rec->{path} && length $rec->{path} ? $rec->{path} : '-';
        my $samples = ($self->{dur_by_path}{$path} ||= []);
        push @$samples, $rec->{duration_ms};
        shift @$samples while @$samples > 512;   # sliding window of recent samples
        $self->{path_dur_count}{$path}++;
        _note_slowest($self->{slowest}, $rec->{duration_ms}, $path,
            defined $rec->{ip} ? $rec->{ip} : '-');
    }

    if (defined $rec->{ts}) {
        my $ts = $rec->{ts};
        $self->{first_ts} = $ts if !defined $self->{first_ts} || $ts < $self->{first_ts};
        $self->{last_ts}  = $ts if !defined $self->{last_ts}  || $ts > $self->{last_ts};
        my $day = epoch_to_label($ts, 'day');
        $self->{requests_by_day}{$day}++;
        $self->{bytes_by_day}{$day} += $bytes;
        my $minute = int($ts / 60) * 60;
        $self->{minute_counts}{$minute}++;
        my $hour = int($ts / 3600) * 3600;
        $self->{hour_counts}{$hour}++;
    }
    return $self;
}

=head2 top(\%hashref, $n, [$min])

Returns an arrayref of C<< [key, count] >> pairs, at most C<$n> entries,
sorted by descending count with keys ascending as tie-breaker. Uses a
bounded insertion buffer (see L</DESCRIPTION>). Callable as an object
method, a class method (C<< LogHawk::Stats->top(\%h, 10) >>) or a plain
function (C<< top(\%h, 10) >> with the sub imported by hand).

=cut

sub top {
    my ($hash, $n, $min);
    if (defined $_[0] && (!ref($_[0]) || ref($_[0]) eq __PACKAGE__)) {
        ($hash, $n, $min) = @_[1 .. $#_];    # class or object invocation
    }
    else {
        ($hash, $n, $min) = @_;              # plain function invocation
    }
    $n = 10 unless defined $n;
    return [] if $n <= 0 || !$hash || !%$hash;
    my @buf;
    while (my ($k, $v) = each %$hash) {
        next if defined $min && $v < $min;
        next if @buf == $n && ($v < $buf[-1][1] || ($v == $buf[-1][1] && $k gt $buf[-1][0]));
        my $i = 0;
        $i++ while $i < @buf && ($buf[$i][1] > $v || ($buf[$i][1] == $v && $buf[$i][0] le $k));
        splice(@buf, $i, 0, [ $k, $v ]);
        pop @buf while @buf > $n;
    }
    return \@buf;
}

=head2 summary(%options)

Builds a plain data structure describing everything the aggregator saw.
Options: C<top> (N per list, default 10). Keys:

    overview   { total, errors, error_rate, bytes_total, bytes_human,
                 bytes_avg, bytes_max, uniq_ips, uniq_urls, uniq_uas,
                 first_ts, last_ts, first_iso, last_iso, span_seconds,
                 rps_avg, peak_minute {epoch,label,count},
                 peak_hour {epoch,label,count}, types {...} }
    status     { classes {}, codes_top [[c,n]..], codes {} }
    top_ips    [[ip, count, bytes]..]
    top_urls   [[path, count, bytes]..]
    top_referers [[ref, count]..]
    top_uas    [[ua, count]..]
    browsers   [[name, count]..]    oses    [[name, count]..]
    devices    [[name, count]..]    ua_kinds [[kind, count]..]
    methods    [[m, count]..]       levels  [[l, count]..]
    hosts/users/programs  [[k, count]..]
    days       [[YYYY-MM-DD, requests, bytes]..]
    durations  undef or { count, avg_ms, p50_ms, p95_ms, p99_ms, max_ms }
    latency    undef or {
                 paths   [[path, timed_requests, avg_ms, p50_ms, p95_ms, max_ms]..]
                         sorted by p95 descending, at most C<top> entries;
                         per-path percentiles use a sliding window of the
                         512 most recent samples per path
                 slowest [[ms, path, ip]..] up to 10 slowest requests
               }

=cut

sub summary {
    my ($self, %opt) = @_;
    my $topn = defined $opt{top} ? $opt{top} : 10;

    my %overview = (
        total      => $self->{total},
        errors     => $self->{error_count},
        error_rate => pct($self->{error_count}, $self->{total}),
        bytes_total => $self->{bytes_total},
        bytes_human => human_size($self->{bytes_total}),
        bytes_avg   => $self->{total} ? int($self->{bytes_total} / $self->{total}) : 0,
        bytes_max   => $self->{bytes_max},
        uniq_ips    => scalar keys %{ $self->{ips} },
        uniq_urls   => scalar keys %{ $self->{urls} },
        uniq_uas    => scalar keys %{ $self->{uas} },
        first_ts    => $self->{first_ts},
        last_ts     => $self->{last_ts},
        first_iso   => defined $self->{first_ts} ? epoch_to_iso($self->{first_ts}) : undef,
        last_iso    => defined $self->{last_ts} ? epoch_to_iso($self->{last_ts}) : undef,
        types       => { %{ $self->{types} } },
    );
    if (defined $self->{first_ts} && defined $self->{last_ts}) {
        my $span = $self->{last_ts} - $self->{first_ts};
        $overview{span_seconds} = $span;
        $overview{rps_avg} = $span > 0
            ? sprintf('%.3f', $self->{total} / $span)
            : sprintf('%.3f', 0);
    }

    my $peak_minute = $self->top($self->{minute_counts}, 1);
    if (@$peak_minute) {
        $overview{peak_minute} = {
            epoch => $peak_minute->[0][0],
            label => epoch_to_label($peak_minute->[0][0], 'minute'),
            count => $peak_minute->[0][1],
        };
    }
    my $peak_hour = $self->top($self->{hour_counts}, 1);
    if (@$peak_hour) {
        $overview{peak_hour} = {
            epoch => $peak_hour->[0][0],
            label => epoch_to_label($peak_hour->[0][0], 'hour'),
            count => $peak_hour->[0][1],
        };
    }

    my @top_ips = map { [ $_->[0], $_->[1], $self->{ips_bytes}{ $_->[0] } ] }
        @{ $self->top($self->{ips}, $topn) };
    my @top_urls = map { [ $_->[0], $_->[1], $self->{urls_bytes}{ $_->[0] } ] }
        @{ $self->top($self->{urls}, $topn) };

    my %durations;
    if (@{ $self->{durations} }) {
        my $d = $self->{durations};
        %durations = (
            count  => scalar @$d,
            avg_ms => int(mean($d) + 0.5),
            p50_ms => int(percentile($d, 50) + 0.5),
            p95_ms => int(percentile($d, 95) + 0.5),
            p99_ms => int(percentile($d, 99) + 0.5),
            max_ms => (sort { $b <=> $a } @$d)[0],
        );
    }

    my $latency;
    if (%{ $self->{dur_by_path} }) {
        my @paths;
        for my $path (sort keys %{ $self->{dur_by_path} }) {
            my $d = $self->{dur_by_path}{$path};
            next unless @$d;
            push @paths, [
                $path,
                $self->{path_dur_count}{$path} // scalar(@$d),
                int(mean($d) + 0.5),
                int(percentile($d, 50) + 0.5),
                int(percentile($d, 95) + 0.5),
                max_of($d),
            ];
        }
        @paths = sort { $b->[4] <=> $a->[4] || $b->[2] <=> $a->[2] || $a->[0] cmp $b->[0] } @paths;
        @paths = @paths[0 .. $topn - 1] if @paths > $topn;
        my @slow = map { [ $_->[0], $_->[1], $_->[2] ] } @{ $self->{slowest} };
        $latency = { paths => \@paths, slowest => \@slow };
    }

    my @days = map { [ $_, $self->{requests_by_day}{$_}, $self->{bytes_by_day}{$_} ] }
        sort { $a cmp $b } keys %{ $self->{requests_by_day} };

    return {
        overview     => \%overview,
        status       => {
            classes  => { %{ $self->{status_classes} } },
            codes    => { %{ $self->{status_codes} } },
            codes_top => $self->top($self->{status_codes}, $topn),
        },
        top_ips      => \@top_ips,
        top_urls     => \@top_urls,
        top_referers => $self->top($self->{referers}, 5),
        top_uas      => $self->top($self->{uas}, $topn),
        browsers     => $self->top($self->{browsers}, $topn),
        oses         => $self->top($self->{oses}, $topn),
        devices      => $self->top($self->{devices}, $topn),
        ua_kinds     => $self->top($self->{ua_kinds}, $topn),
        methods      => $self->top($self->{methods}, $topn),
        levels       => $self->top($self->{levels}, $topn),
        hosts        => $self->top($self->{hosts}, $topn),
        users        => $self->top($self->{users}, $topn),
        programs     => $self->top($self->{programs}, $topn),
        days         => \@days,
        durations    => %durations ? \%durations : undef,
        latency      => $latency,
    };
}

=head2 uniq_count(\%hashref)

Number of distinct keys in a counter hash (sugar for C<scalar keys>).

=head2 _note_slowest(\@buf, $ms, $path, $ip)

Internal bounded insertion buffer keeping the ten slowest individual
requests seen so far as C<< [ms, path, ip] >> triples, sorted by
duration descending. O(10) per record, no full sort of the request
stream.

=cut

sub _note_slowest {
    my ($buf, $ms, $path, $ip) = @_;
    return if @$buf == 10 && $ms <= $buf->[-1][0];
    my $i = 0;
    $i++ while $i < @$buf && $buf->[$i][0] >= $ms;
    splice(@$buf, $i, 0, [ $ms, $path, $ip ]);
    pop @$buf while @$buf > 10;
    return;
}

sub uniq_count {
    my ($self, $hash) = @_;
    return scalar keys %$hash;
}

1;

__END__

=head1 USER-AGENT CLASSIFICATION

C<parse_ua> ships hand-tuned regex tables covering the agents most
commonly seen in server logs:

=over 4

=item * Chromium family: Chrome, Chromium, Edge (all C<Edg/*> variants), Opera (C<OPR/*>), Android WebView

=item * Gecko / WebKit: Firefox, Safari (with C<Version/x> version extraction), Internet Explorer (both C<MSIE> and C<Trident/rv:> forms)

=item * Command-line and library clients: curl, Wget, python-requests, python-urllib, Go, Java/Apache HttpClient, libwww-perl, Node.js

=item * Crawlers: Googlebot, Bingbot, YandexBot, DuckDuckBot, Baiduspider, AhrefsBot, SemrushBot, social expanders, plus a generic C<bot|spider|crawler> fallback

=back

Because Edge/Opera embed Chrome tokens and crawlers often impersonate
browsers, rules are ordered most-specific-first and the first hit wins.
Device class is derived from OS tokens (iPhone -> Mobile, iPad ->
Tablet, Android without C<Tablet> -> Mobile, everything else Desktop)
and overridden to Bot for crawler kinds.

=head1 AUTHOR

Bui Bao Khanh

=head1 SEE ALSO

L<loghawk>, L<LogHawk::Parser>, L<LogHawk::Series>, L<LogHawk::Report>

=cut
