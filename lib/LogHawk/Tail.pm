package LogHawk::Tail;

use strict;
use warnings;
use Time::HiRes qw(sleep time);
use LogHawk::Parser ();
use LogHawk::Anomaly ();
use LogHawk::Util qw(epoch_to_label);

our $VERSION = '1.0.0';

=head1 NAME

LogHawk::Tail - follow-mode with rotation tolerance and live alerting

=head1 SYNOPSIS

    use LogHawk::Tail;

    my $tail = LogHawk::Tail->new(
        file         => '/var/log/nginx/access.log',
        from_start   => 0,
        interval     => 0.25,
        on_record    => sub { my ($rec, $line) = @_; print $line, "\n" },
        on_spike     => sub { my ($point) = @_; warn "ALERT: $point->{label} z=$point->{zscore}\n" },
        max_runtime  => 3600,          # give up after one hour (0 = forever)
    );
    my $stats = $tail->run;
    print "saw $stats->{lines} lines in $stats->{runtime}s\n";

=head1 DESCRIPTION

Re-implements the parts of C<tail -F> that matter for log monitoring:

=over 4

=item * starts at EOF unless C<from_start>;

=item * tolerates inode rotation (logrotate's move-then-create): when
the watched file's C<(dev, ino)> changes, the handle is reopened and an
C<on_rotate> callback fires;

=item * tolerates truncation: when the file shrinks under us, we seek
back to 0 and continue (C<on_truncate> fires);

=item * never blocks longer than C<interval> seconds between checks, so
Ctrl-C and stop-flags stay responsive;

=item * maintains a live per-minute request series and runs rolling
z-score detection (L<LogHawk::Anomaly>) on each completed minute,
emitting C<on_spike> alerts.

=back

=cut

=head1 METHODS

=head2 new(%options)

    file            path to follow, or '-' for STDIN
    from_start      0 = start at EOF (default), 1 = replay the file
    interval        poll sleep in seconds (default 0.25)
    parser          existing LogHawk::Parser (a fresh one is made otherwise)
    on_record       cb->($rec, $line)
    on_error        cb->($line, $parser_stats)   - unparsable lines
    on_spike        cb->($point, $event_history) - anomaly alerts
    on_rotate       cb->($old_path)
    on_truncate     cb->()
    alert_threshold z-score threshold            (default 3.0)
    alert_sensitivity  low|medium|high           (alternative to threshold)
    alert_window    baseline window in minutes   (default 30)
    max_runtime     seconds before run() returns (default 0 = unlimited)
    max_lines       stop after N lines           (default 0 = unlimited)

Callbacks may call C<< $tail->stop >> to end the loop cleanly.

=cut

sub new {
    my ($class, %opt) = @_;
    my $self = {
        file              => $opt{file} // '-',
        from_start        => $opt{from_start} ? 1 : 0,
        interval          => defined $opt{interval} && $opt{interval} > 0 ? $opt{interval} : 0.25,
        parser            => $opt{parser} || LogHawk::Parser->new(keep_raw => 0),
        on_record         => $opt{on_record},
        on_error          => $opt{on_error},
        on_spike          => $opt{on_spike},
        on_rotate         => $opt{on_rotate},
        on_truncate       => $opt{on_truncate},
        alert_threshold   => $opt{alert_threshold},
        alert_sensitivity => $opt{alert_sensitivity},
        alert_window      => defined $opt{alert_window} ? $opt{alert_window} : 30,
        max_runtime       => $opt{max_runtime} || 0,
        max_lines         => $opt{max_lines} || 0,
        _stop             => 0,
    };
    return bless $self, $class;
}

=head2 stop

Sets the stop flag; the next loop iteration exits C<run()>.

=head2 stats

Snapshot of the counters of the last (or current) C<run()>:
C<lines, records, skipped, rotations, truncates, spikes, buckets, runtime>.

=cut

sub stop { $_[0]{_stop} = 1 }

sub stats { return $_[0]{_stats} }

=head2 run

Enters the follow loop. Returns the final stats hashref. C<croak>s if
the file cannot be opened initially; transient reopen failures during
rotation are retried on subsequent polls.

=cut

sub run {
    my ($self) = @_;
    $self->{_stop} = 0;
    my $stats = $self->{_stats} = {
        lines     => 0,
        records   => 0,
        skipped   => 0,
        rotations => 0,
        truncates => 0,
        spikes    => 0,
        buckets   => 0,
        runtime   => 0,
    };
    my $start = time();

    my ($fh, $dev, $ino, $is_stdin) = $self->_open;
    my @history;

    while (!$self->{_stop}) {
        last if $self->{max_runtime} && (time() - $start) >= $self->{max_runtime};
        last if $self->{max_lines} && $stats->{lines} >= $self->{max_lines};

        # Drain everything currently available.
        my $read_any = 0;
        while (defined(my $line = <$fh>)) {
            $read_any = 1;
            $line =~ s/\r?\n\z//;
            $stats->{lines}++;
            $self->_ingest($line, $stats, \@history);
            last if $self->{_stop};
            last if $self->{max_lines} && $stats->{lines} >= $self->{max_lines};
        }

        unless ($is_stdin) {
            my @st = stat $self->{file};
            if (@st && $st[1] != $ino) {
                # rotated: old path now points at a different inode
                $stats->{rotations}++;
                $self->{on_rotate}->($self->{file}) if $self->{on_rotate};
                close $fh;
                ($fh, $dev, $ino) = $self->_open;
            }
            elsif (@st && tell($fh) > $st[7] + 0 && $st[7] > 0) {
                # truncated in place (copytruncate)
                $stats->{truncates}++;
                $self->{on_truncate}->() if $self->{on_truncate};
                seek($fh, 0, 0);
            }
        }

        sleep($self->{interval});
    }

    $stats->{runtime} = sprintf('%.2f', time() - $start) + 0;
    close $fh unless $is_stdin;
    return $stats;
}

# One line in: parse, dispatch callbacks, update the alert bucket.
sub _ingest {
    my ($self, $line, $stats, $history) = @_;
    my $rec = $self->{parser}->parse_line($line);
    if ($rec) {
        $stats->{records}++;
        $self->{on_record}->($rec, $line) if $self->{on_record};
        $self->_tick_alert($rec->{ts}, $rec, $stats, $history);
    }
    else {
        my $pstats = $self->{parser}->stats;
        $stats->{skipped} = $pstats->{skipped};
        $self->{on_error}->($line, $pstats) if $self->{on_error};
    }
    return $self;
}

# Per-minute counting + anomaly check whenever the minute rolls over.
sub _tick_alert {
    my ($self, $ts, $rec, $stats, $history) = @_;
    my $now = defined $ts && $ts > 0 ? $ts : time();
    my $bucket = int($now / 60) * 60;

    if (!defined $self->{_cur_bucket}) {
        $self->{_cur_bucket} = $bucket;
        $self->{_cur_count}  = 0;
    }
    elsif ($bucket != $self->{_cur_bucket}) {
        my $point = {
            epoch => $self->{_cur_bucket},
            label => epoch_to_label($self->{_cur_bucket}, 'minute'),
            value => $self->{_cur_count},
        };
        $stats->{buckets}++;
        $self->_check_spike($point, $history, $stats);
        $self->{_cur_bucket} = $bucket;
        $self->{_cur_count}  = 0;
    }
    $self->{_cur_count}++;
    return $self;
}

sub _check_spike {
    my ($self, $point, $history, $stats) = @_;
    push @$history, $point;
    shift @$history while @$history > 240;
    return unless $self->{on_spike};

    my %opt = (window => $self->{alert_window}, min_history => 10);
    $opt{threshold}   = $self->{alert_threshold} if defined $self->{alert_threshold};
    $opt{sensitivity} = $self->{alert_sensitivity}
        if !defined $self->{alert_threshold} && defined $self->{alert_sensitivity};
    my $det = LogHawk::Anomaly->new(%opt);
    return unless @$history >= $det->{min_history} + 1;

    # Score only the final bucket against the prior history.
    my $probe = [ @$history[ 0 .. $#$history - 1 ], $point ];
    my $res = $det->detect($probe);
    if (@{ $res->{points} }) {
        for my $p (@{ $res->{points} }) {
            $stats->{spikes}++;
            $self->{on_spike}->($p, $res->{events});
        }
    }
    return $self;
}

sub _open {
    my ($self) = @_;
    if ($self->{file} eq '-') {
        return (\*STDIN, undef, undef, 1);
    }
    open(my $fh, '<', $self->{file})
        or die "loghawk tailf: cannot open '$self->{file}': $!\n";
    unless ($self->{from_start}) {
        seek($fh, 0, 2);    # jump to EOF
    }
    my @st = stat $self->{file};
    return ($fh, @st ? ($st[0], $st[1]) : (undef, undef), 0);
}

1;

__END__

=head1 ROTATION SEMANTICS

logrotate's two common strategies are handled explicitly:

=over 4

=item * I<create> (rename + new file): the inode under the same path
changes; LogHawk notices the C<stat> mismatch, closes its handle and
reopens the path, continuing from the new file's beginning.

=item * I<copytruncate>: the inode stays but the size collapses; the
position becomes larger than the file, so LogHawk seeks to 0. A tiny
race window (writes between copy and truncate) is inherent to that
strategy and can at worst duplicate a few lines - identical to what
C<tail -F> does.

=back

=head1 AUTHOR

Bui Bao Khanh

=head1 SEE ALSO

L<loghawk>, L<LogHawk::Anomaly>, L<LogHawk::Parser>

=cut
