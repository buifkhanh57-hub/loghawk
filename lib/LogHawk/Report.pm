package LogHawk::Report;

use strict;
use warnings;
use Carp qw(croak);
use POSIX qw(strftime);
use LogHawk::Anomaly ();
use LogHawk::Util qw(
    human_size human_num pct truncate_str epoch_to_iso status_class
);
use LogHawk::Series qw(ascii_chart);

our $VERSION = '1.0.0';

=head1 NAME

LogHawk::Report - text, markdown and HTML report renderers

=head1 SYNOPSIS

    use LogHawk::Report;

    my $ctx = {
        title     => 'Nightly report',
        source    => 'access.log',
        generated => '2025-11-18T04:00:00Z',
        filter    => 'status in [5xx]',
        summary   => $stats_summary,     # LogHawk::Stats::summary
        series    => $series_result,     # LogHawk::Series::bucketize (optional)
        anomalies => $anomaly_result,    # LogHawk::Anomaly::detect (optional)
    };

    print LogHawk::Report::render('text', $ctx);
    print LogHawk::Report::render('markdown', $ctx);
    print LogHawk::Report::render('html', $ctx);

=head1 DESCRIPTION

Pure presentation layer: consumes the plain data structures produced by
L<LogHawk::Stats>, L<LogHawk::Series> and L<LogHawk::Anomaly> and turns
them into three output formats. All renderers tolerate missing sections
- pass only C<summary> and you get the overview tables, pass a series
and a chart is added, pass anomalies and the incident table appears.

=cut

my $WIDTH = 78;

=head2 render($format, $ctx)

Dispatches to C<render_text>, C<render_markdown> or C<render_html>.
C<$format> is case-insensitive and accepts the aliases C<md> and C<htm>.
Unknown formats C<croak>.

=cut

sub render {
    my ($format, $ctx) = @_;
    croak('render needs a context hashref') unless ref($ctx) eq 'HASH';
    $format = lc($format // 'text');
    return render_text($ctx)     if $format eq 'text' || $format eq 'txt';
    return render_markdown($ctx) if $format eq 'markdown' || $format eq 'md';
    return render_html($ctx)     if $format eq 'html' || $format eq 'htm';
    croak("unknown report format '$format' (want text|markdown|html)");
}

# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------

sub _section {
    my ($parts, $title) = @_;
    push @$parts, '', uc($title), '-' x length($title);
    return $parts;
}

sub _table {
    my ($cols, $rows) = @_;
    my @out;
    my @w;
    for my $i (0 .. $#$cols) {
        $w[$i] = length $cols->[$i]{title};
    }
    for my $row (@$rows) {
        for my $i (0 .. $#$cols) {
            my $l = length(defined $row->[$i] ? $row->[$i] : '');
            $w[$i] = $l if $l > $w[$i];
        }
    }
    for my $i (0 .. $#$cols) {
        $w[$i] = $cols->[$i]{max} if $cols->[$i]{max} && $w[$i] > $cols->[$i]{max};
    }
    my $fmt_row = sub {
        my ($row) = @_;
        my @cells;
        for my $i (0 .. $#$cols) {
            my $v = defined $row->[$i] ? "$row->[$i]" : '';
            my $w = $w[$i];
            if (length($v) > $w) {
                $v = truncate_str($v, $w);
            }
            push @cells, $cols->[$i]{align} eq 'r'
                ? sprintf('%*s', $w, $v)
                : sprintf('%-*s', $w, $v);
        }
        return '  ' . join('  ', @cells);
    };
    push @out, $fmt_row->([ map { $_->{title} } @$cols ]);
    push @out, '  ' . join('  ', map { '-' x $w[$_] } 0 .. $#$cols);
    push @out, $fmt_row->($_) for @$rows;
    return \@out;
}

sub _bar {
    my ($value, $max, $width) = @_;
    return '' unless $max > 0;
    my $len = int($value / $max * $width + 0.5);
    $len = 1 if $value > 0 && $len < 1;
    return '#' x $len;
}

sub _row_max {
    my ($rows, $idx) = @_;
    my $max = 0;
    for my $r (@$rows) {
        $max = $r->[$idx] if defined $r->[$idx] && $r->[$idx] > $max;
    }
    return $max;
}

sub _fmt_count_bytes {
    my ($n, $bytes) = @_;
    return (human_num($n), human_size($bytes));
}

sub _ov {
    my ($ctx, $key) = @_;
    my $s = $ctx->{summary};
    return undef unless $s && $s->{overview};
    return $s->{overview}{$key};
}

sub _h {
    my ($s) = @_;
    return '' unless defined $s;
    $s =~ s/&/&amp;/g;
    $s =~ s/</&lt;/g;
    $s =~ s/>/&gt;/g;
    $s =~ s/"/&quot;/g;
    return $s;
}

# ---------------------------------------------------------------------------
# TEXT
# ---------------------------------------------------------------------------

=head2 render_text($ctx)

78-column terminal report: boxed header, overview block, status table,
top-N tables with ASCII distribution bars, day bandwidth table and -
when present in the context - the series chart and anomaly tables.

=cut

sub render_text {
    my ($ctx) = @_;
    my @out;

    my $title = $ctx->{title} // 'LogHawk Report';
    my $pad = int(($WIDTH - length($title)) / 2);
    $pad = 0 if $pad < 0;
    push @out, '=' x $WIDTH;
    push @out, ' ' x $pad . $title;
    push @out, '=' x $WIDTH;

    push @out, sprintf('Source    : %s', $ctx->{source}   // '-');
    push @out, sprintf('Generated : %s', $ctx->{generated} // strftime('%Y-%m-%dT%H:%M:%SZ', gmtime()));
    push @out, sprintf('Filter    : %s', $ctx->{filter}    // 'none');

    if (my $ov = $ctx->{summary}{overview}) {
        _section(\@out, 'Overview');
        push @out, sprintf('Requests      : %s', human_num($ov->{total}));
        push @out, sprintf('Parse types   : %s',
            join(', ', map { "$_=$ov->{types}{$_}" } sort keys %{ $ov->{types} || {} }) || '-');
        push @out, sprintf('Bandwidth     : %s (avg %s/req, max %s)',
            $ov->{bytes_human}, human_size($ov->{bytes_avg} // 0), human_size($ov->{bytes_max} // 0));
        push @out, sprintf('Unique IPs    : %s', human_num($ov->{uniq_ips}));
        push @out, sprintf('Unique URLs   : %s', human_num($ov->{uniq_urls}));
        push @out, sprintf('Errors        : %s (%s%%)',
            human_num($ov->{errors}), $ov->{error_rate});
        if (defined $ov->{first_iso}) {
            push @out, sprintf('Span          : %s -> %s (%ss, avg %s rps)',
                $ov->{first_iso}, $ov->{last_iso}, human_num($ov->{span_seconds}), $ov->{rps_avg});
        }
        if (my $pm = $ov->{peak_minute}) {
            push @out, sprintf('Peak minute   : %s (%s requests)', $pm->{label}, human_num($pm->{count}));
        }
        if (my $ph = $ov->{peak_hour}) {
            push @out, sprintf('Peak hour     : %s (%s requests)', $ph->{label}, human_num($ph->{count}));
        }
    }

    my $s = $ctx->{summary};
    if ($s && $s->{status}) {
        _section(\@out, 'Status Codes');
        my $total = $s->{overview}{total} || 1;
        my @cls_rows = map { [ $_, human_num($s->{status}{classes}{$_}),
                               pct($s->{status}{classes}{$_}, $total) . '%' ] }
            sort { $a cmp $b } keys %{ $s->{status}{classes} };
        my $t = _table(
            [ { title => 'CLASS', align => 'l' }, { title => 'COUNT', align => 'r' }, { title => 'SHARE', align => 'r' } ],
            \@cls_rows,
        );
        push @out, @$t;
        push @out, '';
        my @code_rows;
        my $codes = $s->{status}{codes_top};
        my $cmax = _row_max($codes, 1);
        for my $c (@$codes) {
            push @code_rows, [ $c->[0], human_num($c->[1]),
                               pct($c->[1], $total) . '%', _bar($c->[1], $cmax, 30) ];
        }
        $t = _table(
            [ { title => 'CODE', align => 'l' }, { title => 'COUNT', align => 'r' },
              { title => 'SHARE', align => 'r' }, { title => 'DISTRIBUTION', align => 'l' } ],
            \@code_rows,
        );
        push @out, @$t;
    }

    if ($s && @{ $s->{top_ips} }) {
        _section(\@out, 'Top Client IPs');
        my $imax = _row_max($s->{top_ips}, 1);
        my @rows;
        my $rank = 1;
        for my $row (@{ $s->{top_ips} }) {
            push @rows, [ $rank++, $row->[0], human_num($row->[1]),
                          human_size($row->[2] // 0), _bar($row->[1], $imax, 24) ];
        }
        my $t = _table(
            [ { title => '#', align => 'r' }, { title => 'IP', align => 'l' },
              { title => 'REQS', align => 'r' }, { title => 'BYTES', align => 'r' },
              { title => 'LOAD', align => 'l' } ],
            \@rows,
        );
        push @out, @$t;
    }

    if ($s && @{ $s->{top_urls} }) {
        _section(\@out, 'Top URLs');
        my @rows;
        my $rank = 1;
        for my $row (@{ $s->{top_urls} }) {
            push @rows, [ $rank++, $row->[0], human_num($row->[1]), human_size($row->[2] // 0) ];
        }
        my $t = _table(
            [ { title => '#', align => 'r' }, { title => 'PATH', align => 'l', max => 44 },
              { title => 'REQS', align => 'r' }, { title => 'BYTES', align => 'r' } ],
            \@rows,
        );
        push @out, @$t;
    }

    if ($s && @{ $s->{days} }) {
        _section(\@out, 'Bandwidth by Day');
        my @rows;
        for my $d (@{ $s->{days} }) {
            push @rows, [ $d->[0], human_num($d->[1]), human_size($d->[2]),
                          human_size($d->[1] ? int($d->[2] / $d->[1]) : 0) ];
        }
        my $t = _table(
            [ { title => 'DAY', align => 'l' }, { title => 'REQUESTS', align => 'r' },
              { title => 'BYTES', align => 'r' }, { title => 'AVG/REQ', align => 'r' } ],
            \@rows,
        );
        push @out, @$t;
    }

    for my $spec (
        ['Browsers', 'browsers'], ['Operating Systems', 'oses'],
        ['Devices', 'devices'], ['U-A Kinds', 'ua_kinds'],
        ['Methods', 'methods'], ['Log Levels', 'levels'],
    ) {
        my ($label, $key) = @$spec;
        next unless $s && @{ $s->{$key} || [] };
        _section(\@out, $label);
        my @rows = map { [ $_->[0], human_num($_->[1]), pct($_->[1], $s->{overview}{total}) . '%' ] }
            @{ $s->{$key} };
        my $t = _table(
            [ { title => 'NAME', align => 'l' }, { title => 'COUNT', align => 'r' },
              { title => 'SHARE', align => 'r' } ],
            \@rows,
        );
        push @out, @$t;
    }

    if ($s && $s->{durations}) {
        _section(\@out, 'Response Durations');
        my $d = $s->{durations};
        push @out, sprintf('count %s   avg %dms   p50 %dms   p95 %dms   p99 %dms   max %dms',
            human_num($d->{count}), $d->{avg_ms}, $d->{p50_ms}, $d->{p95_ms}, $d->{p99_ms}, $d->{max_ms});
    }

    if ($s && $s->{latency} && @{ $s->{latency}{paths} }) {
        _section(\@out, 'Latency by Path (ms)');
        my @rows = map {
            [ $_->[0], human_num($_->[1]), $_->[2], $_->[3], $_->[4], $_->[5] ]
        } @{ $s->{latency}{paths} };
        my $t = _table(
            [ { title => 'PATH', align => 'l', max => 34 }, { title => 'TIMED', align => 'r' },
              { title => 'AVG', align => 'r' }, { title => 'P50', align => 'r' },
              { title => 'P95', align => 'r' }, { title => 'MAX', align => 'r' } ],
            \@rows,
        );
        push @out, @$t;
        if (@{ $s->{latency}{slowest} }) {
            push @out, '';
            push @out, 'Slowest requests:';
            for my $w (@{ $s->{latency}{slowest} }) {
                push @out, sprintf('  %6d ms  %-34s  %s', $w->[0], truncate_str($w->[1], 34), $w->[2]);
            }
        }
    }

    if ($ctx->{series} && @{ $ctx->{series}{series} }) {
        my $ser = $ctx->{series};
        _section(\@out, "Series ($ser->{unit}, value=$ser->{value})");
        push @out, ascii_chart($ser->{series}, value => $ser->{value}, rows => 40, bar_width => 36);
        my $st = $ser->{stats};
        push @out, sprintf('buckets %s  total %s  mean %.2f  sd %.2f  peak %s',
            human_num($st->{buckets}), human_num($st->{total}), $st->{mean}, $st->{sd},
            defined $st->{peak_label} ? "$st->{peak}@$st->{peak_label}" : '-');
    }

    if ($ctx->{anomalies} && @{ $ctx->{anomalies}{points} || [] }) {
        my $an = $ctx->{anomalies};
        _section(\@out, 'Anomalies');
        push @out, sprintf('window %d buckets, threshold z>=%.2f, mode %s, risk %.2f',
            $an->{config}{window}, $an->{config}{threshold}, $an->{config}{mode}, $an->{risk});
        push @out, '';
        my @rows = map {
            [ $_->{label}, human_num($_->{value}), sprintf('%.2f', $_->{baseline_mean}),
              sprintf('%.2f', $_->{zscore}), $_->{direction}, $_->{severity} ]
        } @{ $an->{points} };
        my $t = _table(
            [ { title => 'BUCKET', align => 'l' }, { title => 'VALUE', align => 'r' },
              { title => 'MEAN', align => 'r' }, { title => 'Z', align => 'r' },
              { title => 'DIR', align => 'l' }, { title => 'SEVERITY', align => 'l' } ],
            \@rows,
        );
        push @out, @$t;
        if (@{ $an->{events} }) {
            push @out, '';
            push @out, 'Incident summary:';
            push @out, "  - " . LogHawk::Anomaly::describe_event($_) for @{ $an->{events} };
        }
    }
    elsif ($ctx->{anomalies}) {
        _section(\@out, 'Anomalies');
        push @out, 'none detected within the configured sensitivity';
    }

    push @out, '', '=' x $WIDTH;
    push @out, 'loghawk report - by Bui Bao Khanh';
    return join("\n", @out) . "\n";
}

# ---------------------------------------------------------------------------
# MARKDOWN
# ---------------------------------------------------------------------------

=head2 render_markdown($ctx)

GitHub-flavoured markdown: h1 title, metadata bullet list, one h2 per
section, standard pipe tables. The series chart is embedded as a fenced
code block so it survives in READMEs and pull requests.

=cut

sub render_markdown {
    my ($ctx) = @_;
    my @out;

    push @out, '# ' . ($ctx->{title} // 'LogHawk Report'), '';
    push @out, '- **Source:** ' . ($ctx->{source} // '-');
    push @out, '- **Generated:** ' . ($ctx->{generated} // '-');
    push @out, '- **Filter:** `' . ($ctx->{filter} // 'none') . '`';
    push @out, '';

    if (my $ov = $ctx->{summary}{overview}) {
        push @out, '## Overview', '';
        push @out, '| Metric | Value |';
        push @out, '|---|---:|';
        push @out, "| Requests | " . human_num($ov->{total}) . " |";
        push @out, "| Bandwidth | " . $ov->{bytes_human} . " |";
        push @out, "| Unique IPs | " . human_num($ov->{uniq_ips}) . " |";
        push @out, "| Unique URLs | " . human_num($ov->{uniq_urls}) . " |";
        push @out, "| Errors | " . human_num($ov->{errors}) . " (" . $ov->{error_rate} . "%) |";
        if (defined $ov->{first_iso}) {
            push @out, "| Span | $ov->{first_iso} -> $ov->{last_iso} |";
            push @out, "| Avg rate | $ov->{rps_avg} req/s |";
        }
        if (my $pm = $ov->{peak_minute}) {
            push @out, "| Peak minute | $pm->{label} (" . human_num($pm->{count}) . " req) |";
        }
        push @out, '';
    }

    my $s = $ctx->{summary};
    if ($s && $s->{status}) {
        push @out, '## Status Codes', '';
        push @out, '| Class | Count |', '|---|---:|';
        for my $c (sort keys %{ $s->{status}{classes} }) {
            push @out, "| $c | " . human_num($s->{status}{classes}{$c}) . " |";
        }
        push @out, '';
        push @out, '| Code | Count |', '|---|---:|';
        for my $c (@{ $s->{status}{codes_top} }) {
            push @out, "| $c->[0] | " . human_num($c->[1]) . " |";
        }
        push @out, '';
    }

    for my $spec (
        ['Top Client IPs', 'top_ips', 1], ['Top URLs', 'top_urls', 1],
        ['Browsers', 'browsers', 0], ['Operating Systems', 'oses', 0],
        ['Devices', 'devices', 0], ['Methods', 'methods', 0],
    ) {
        my ($label, $key, $with_bytes) = @$spec;
        next unless $s && @{ $s->{$key} || [] };
        push @out, "## $label", '';
        if ($with_bytes) {
            push @out, '| # | ' . ($key eq 'top_ips' ? 'IP' : 'Path') . ' | Requests | Bytes |';
            push @out, '|---:|---|---:|---:|';
            my $rank = 1;
            for my $row (@{ $s->{$key} }) {
                push @out, "| " . $rank++ . " | " . _h($row->[0]) . " | "
                    . human_num($row->[1]) . " | " . human_size($row->[2] // 0) . " |";
            }
        }
        else {
            push @out, '| Name | Count |', '|---|---:|';
            for my $row (@{ $s->{$key} }) {
                push @out, "| " . _h($row->[0]) . " | " . human_num($row->[1]) . " |";
            }
        }
        push @out, '';
    }

    if ($s && @{ $s->{days} }) {
        push @out, '## Bandwidth by Day', '';
        push @out, '| Day | Requests | Bytes | Avg/Req |';
        push @out, '|---|---:|---:|---:|';
        for my $d (@{ $s->{days} }) {
            push @out, "| $d->[0] | " . human_num($d->[1]) . " | " . human_size($d->[2])
                . " | " . human_size($d->[1] ? int($d->[2] / $d->[1]) : 0) . " |";
        }
        push @out, '';
    }

    if ($s && $s->{latency} && @{ $s->{latency}{paths} }) {
        push @out, '## Latency by Path (ms)', '';
        push @out, '| Path | Timed | Avg | P50 | P95 | Max |';
        push @out, '|---|---:|---:|---:|---:|---:|';
        for my $p (@{ $s->{latency}{paths} }) {
            push @out, '| ' . _h($p->[0]) . " | " . human_num($p->[1])
                . " | $p->[2] | $p->[3] | $p->[4] | $p->[5] |";
        }
        if (@{ $s->{latency}{slowest} }) {
            push @out, '', '### Slowest requests', '';
            for my $w (@{ $s->{latency}{slowest} }) {
                push @out, "- $w->[0] ms - `" . _h($w->[1]) . "` from $w->[2]";
            }
        }
        push @out, '';
    }

    if ($ctx->{series} && @{ $ctx->{series}{series} }) {
        my $ser = $ctx->{series};
        push @out, "## Series (`$ser->{unit}`, value=`$ser->{value}`)", '';
        push @out, '```', ascii_chart($ser->{series}, value => $ser->{value}, rows => 40, bar_width => 36), '```', '';
    }

    if ($ctx->{anomalies} && @{ $ctx->{anomalies}{points} || [] }) {
        my $an = $ctx->{anomalies};
        push @out, '## Anomalies', '';
        push @out, sprintf('window=%d threshold=z>=%.2f mode=%s risk=%.2f', @{$an->{config}}{qw(window threshold mode)}, $an->{risk});
        push @out, '';
        push @out, '| Bucket | Value | Baseline mean | z | Direction | Severity |';
        push @out, '|---|---:|---:|---:|---|---|';
        for my $p (@{ $an->{points} }) {
            push @out, "| $p->{label} | " . human_num($p->{value}) . " | $p->{baseline_mean} | $p->{zscore} | $p->{direction} | $p->{severity} |";
        }
        if (@{ $an->{events} }) {
            push @out, '', '### Incident summary', '';
            push @out, "- " . LogHawk::Anomaly::describe_event($_) for @{ $an->{events} };
        }
        push @out, '';
    }

    push @out, '---', '', '**by Bui Bao Khanh**';
    return join("\n", @out) . "\n";
}

# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

my $CSS = <<'CSS';
  body { font-family: -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
         margin: 2rem auto; max-width: 960px; color: #1f2430; background: #fafbfc; }
  h1 { border-bottom: 3px solid #2f6fdb; padding-bottom: .3rem; }
  h2 { margin-top: 2rem; color: #2f6fdb; }
  .meta { color: #5a6472; font-size: .9rem; }
  table { border-collapse: collapse; width: 100%; margin: .8rem 0; background: #fff; }
  th, td { border: 1px solid #d8dee6; padding: .35rem .6rem; text-align: left; }
  th { background: #eef2f8; }
  tr:nth-child(even) td { background: #f6f8fb; }
  td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
  .ov { background: #fff; border: 1px solid #d8dee6; border-radius: 6px;
        padding: .8rem 1.2rem; }
  .ov div { padding: .15rem 0; }
  .sev-critical { color: #b00020; font-weight: 700; }
  .sev-high     { color: #d35400; font-weight: 700; }
  .sev-medium   { color: #b7950b; font-weight: 600; }
  .sev-low      { color: #5a6472; }
  pre.chart { background: #10141c; color: #9fe3a1; padding: 1rem; overflow-x: auto;
              border-radius: 6px; font-size: .8rem; }
  footer { margin-top: 2.5rem; color: #5a6472; border-top: 1px solid #d8dee6;
           padding-top: .8rem; font-size: .85rem; }
CSS

=head2 render_html($ctx)

Standalone HTML document (embedded CSS, no external assets). Anomaly
severities are styled with severity classes; the series chart is
rendered inside a dark C<pre> block.

=cut

sub render_html {
    my ($ctx) = @_;
    my @out;
    my $title = _h($ctx->{title} // 'LogHawk Report');

    push @out, '<!DOCTYPE html>';
    push @out, '<html lang="en">';
    push @out, '<head>';
    push @out, '<meta charset="utf-8">';
    push @out, '<meta name="viewport" content="width=device-width, initial-scale=1">';
    push @out, "<title>$title</title>";
    push @out, '<style>', $CSS, '</style>';
    push @out, '</head>';
    push @out, '<body>';
    push @out, "<h1>$title</h1>";
    push @out, '<p class="meta">',
        _h('Source: '   . ($ctx->{source} // '-')), ' &middot; ',
        _h('Generated: ' . ($ctx->{generated} // '-')), ' &middot; ',
        _h('Filter: '   . ($ctx->{filter} // 'none')),
        '</p>';

    if (my $ov = $ctx->{summary}{overview}) {
        push @out, '<div class="ov">';
        push @out, '<div><strong>Requests:</strong> ' . human_num($ov->{total}) . '</div>';
        push @out, '<div><strong>Bandwidth:</strong> ' . _h($ov->{bytes_human})
            . ' (avg ' . _h(human_size($ov->{bytes_avg} // 0)) . '/req)</div>';
        push @out, '<div><strong>Unique IPs:</strong> ' . human_num($ov->{uniq_ips})
            . ' &middot; <strong>Unique URLs:</strong> ' . human_num($ov->{uniq_urls}) . '</div>';
        push @out, '<div><strong>Errors:</strong> ' . human_num($ov->{errors})
            . ' (' . _h($ov->{error_rate}) . '%)</div>';
        if (defined $ov->{first_iso}) {
            push @out, '<div><strong>Span:</strong> ' . _h("$ov->{first_iso} -> $ov->{last_iso}")
                . ' (avg ' . _h($ov->{rps_avg}) . ' req/s)</div>';
        }
        if (my $pm = $ov->{peak_minute}) {
            push @out, '<div><strong>Peak minute:</strong> ' . _h($pm->{label})
                . ' (' . human_num($pm->{count}) . ' requests)</div>';
        }
        push @out, '</div>';
    }

    my $s = $ctx->{summary};
    if ($s && $s->{status}) {
        push @out, '<h2>Status Codes</h2>';
        push @out, '<table><tr><th>Class</th><th class="num">Count</th></tr>';
        for my $c (sort keys %{ $s->{status}{classes} }) {
            push @out, "<tr><td>" . _h($c) . "</td><td class=\"num\">"
                . human_num($s->{status}{classes}{$c}) . "</td></tr>";
        }
        push @out, '</table>';
        push @out, '<table><tr><th>Code</th><th class="num">Count</th><th class="num">Share</th></tr>';
        my $total = $s->{overview}{total} || 1;
        for my $c (@{ $s->{status}{codes_top} }) {
            push @out, "<tr><td>" . _h($c->[0]) . "</td><td class=\"num\">"
                . human_num($c->[1]) . "</td><td class=\"num\">"
                . pct($c->[1], $total) . "%</td></tr>";
        }
        push @out, '</table>';
    }

    for my $spec (
        ['Top Client IPs', 'top_ips', 'IP', 1],
        ['Top URLs',       'top_urls', 'Path', 1],
        ['Browsers',       'browsers', 'Name', 0],
        ['Operating Systems', 'oses',  'Name', 0],
        ['Devices',        'devices',  'Name', 0],
        ['Methods',        'methods',  'Method', 0],
    ) {
        my ($label, $key, $colname, $with_bytes) = @$spec;
        next unless $s && @{ $s->{$key} || [] };
        push @out, "<h2>" . _h($label) . "</h2>";
        push @out, '<table><tr><th>#</th><th>' . _h($colname) . '</th>'
            . ($with_bytes ? '<th class="num">Requests</th><th class="num">Bytes</th>'
                           : '<th class="num">Count</th>')
            . '</tr>';
        my $rank = 1;
        for my $row (@{ $s->{$key} }) {
            if ($with_bytes) {
                push @out, "<tr><td class=\"num\">" . $rank++ . "</td><td>" . _h($row->[0])
                    . "</td><td class=\"num\">" . human_num($row->[1])
                    . "</td><td class=\"num\">" . human_size($row->[2] // 0) . "</td></tr>";
            }
            else {
                push @out, "<tr><td class=\"num\">" . $rank++ . "</td><td>" . _h($row->[0])
                    . "</td><td class=\"num\">" . human_num($row->[1]) . "</td></tr>";
            }
        }
        push @out, '</table>';
    }

    if ($s && @{ $s->{days} }) {
        push @out, '<h2>Bandwidth by Day</h2>';
        push @out, '<table><tr><th>Day</th><th class="num">Requests</th><th class="num">Bytes</th><th class="num">Avg/Req</th></tr>';
        for my $d (@{ $s->{days} }) {
            push @out, "<tr><td>" . _h($d->[0]) . "</td><td class=\"num\">" . human_num($d->[1])
                . "</td><td class=\"num\">" . human_size($d->[2]) . "</td><td class=\"num\">"
                . human_size($d->[1] ? int($d->[2] / $d->[1]) : 0) . "</td></tr>";
        }
        push @out, '</table>';
    }

    if ($s && $s->{latency} && @{ $s->{latency}{paths} }) {
        push @out, '<h2>Latency by Path (ms)</h2>';
        push @out, '<table><tr><th>Path</th><th class="num">Timed</th><th class="num">Avg</th>'
            . '<th class="num">P50</th><th class="num">P95</th><th class="num">Max</th></tr>';
        for my $p (@{ $s->{latency}{paths} }) {
            push @out, '<tr><td>' . _h($p->[0]) . '</td><td class="num">' . human_num($p->[1])
                . "</td><td class=\"num\">$p->[2]</td><td class=\"num\">$p->[3]"
                . "</td><td class=\"num\">$p->[4]</td><td class=\"num\">$p->[5]</td></tr>";
        }
        push @out, '</table>';
        if (@{ $s->{latency}{slowest} }) {
            push @out, '<ul>';
            push @out, '<li>' . $_->[0] . ' ms - <code>' . _h($_->[1]) . '</code> from '
                . _h($_->[2]) . '</li>' for @{ $s->{latency}{slowest} };
            push @out, '</ul>';
        }
    }

    if ($ctx->{series} && @{ $ctx->{series}{series} }) {
        my $ser = $ctx->{series};
        push @out, '<h2>Series (' . _h($ser->{unit}) . ', value=' . _h($ser->{value}) . ')</h2>';
        push @out, '<pre class="chart">',
            _h(ascii_chart($ser->{series}, value => $ser->{value}, rows => 40, bar_width => 40)),
            '</pre>';
    }

    if ($ctx->{anomalies}) {
        push @out, '<h2>Anomalies</h2>';
        my $pts = $ctx->{anomalies}{points} || [];
        if (@$pts) {
            my $an = $ctx->{anomalies};
            push @out, '<p class="meta">',
                _h(sprintf('window %d buckets, threshold z>=%.2f, mode %s, risk %.2f',
                    $an->{config}{window}, $an->{config}{threshold},
                    $an->{config}{mode}, $an->{risk})),
                '</p>';
            push @out, '<table><tr><th>Bucket</th><th class="num">Value</th><th class="num">Mean</th>'
                . '<th class="num">z</th><th>Dir</th><th>Severity</th></tr>';
            for my $p (@$pts) {
                push @out, "<tr><td>" . _h($p->{label}) . "</td><td class=\"num\">"
                    . human_num($p->{value}) . "</td><td class=\"num\">$p->{baseline_mean}</td>"
                    . "<td class=\"num\">$p->{zscore}</td><td>" . _h($p->{direction})
                    . "</td><td><span class=\"sev-" . _h($p->{severity}) . "\">"
                    . _h($p->{severity}) . "</span></td></tr>";
            }
            push @out, '</table>';
            if (@{ $ctx->{anomalies}{events} }) {
                push @out, '<ul>';
                push @out, '<li>' . _h(LogHawk::Anomaly::describe_event($_)) . '</li>'
                    for @{ $ctx->{anomalies}{events} };
                push @out, '</ul>';
            }
        }
        else {
            push @out, '<p>No anomalies detected within the configured sensitivity.</p>';
        }
    }

    push @out, '<footer>loghawk report &mdash; by Bui Bao Khanh</footer>';
    push @out, '</body>';
    push @out, '</html>';
    return join("\n", @out) . "\n";
}

1;

__END__

=head1 CONTEXT REFERENCE

All keys are optional; renderers skip absent data:

    title      string
    source     comma-joined input files or 'STDIN'
    generated  ISO timestamp string
    filter     LogHawk::Filters->to_string result
    summary    LogHawk::Stats::summary structure
    series     LogHawk::Series::bucketize result
    anomalies  LogHawk::Anomaly::detect result

HTML output intentionally uses zero external resources so reports can
be emailed or dropped into an S3 bucket as-is.

=head1 AUTHOR

Bui Bao Khanh

=head1 SEE ALSO

L<loghawk>, L<LogHawk::Stats>, L<LogHawk::Series>, L<LogHawk::Anomaly>

=cut
