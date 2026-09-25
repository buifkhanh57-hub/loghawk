#!/usr/bin/perl
# perl-logparser — parse an Apache/Nginx style access log and report stats.
# Usage: perl logparse.pl access.log | perl logparse.pl < access.log
use strict;
use warnings;

my %by_ip;
my %by_status;
my %by_hour;
my $total = 0;
my $bytes_total = 0;

my $LOG_RE = qr/^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d{3}) (\d+|-)/;

while (my $line = <>) {
    chomp $line;
    next unless $line =~ $LOG_RE;

    my ($ip, $time, $method, $path, $status, $size) = ($1, $2, $3, $4, $5, $6);
    $total++;
    $bytes_total += $size eq '-' ? 0 : $size;
    $by_ip{$ip}++;
    $by_status{$status}++;
    if ($time =~ m{:(\d{2}):\d{2} \+}) {   # "[10/Oct/2025:13:55:36 +0700]"
        $by_hour{$1}++;
    }
}

die "No log lines matched the common log format.\n" unless $total;

print "=== Log summary ===\n";
print "total requests : $total\n";
printf "total bytes    : %s\n", commify($bytes_total);
printf "unique IPs     : %d\n", scalar keys %by_ip;

print "\n--- status codes ---\n";
for my $code (sort { $by_status{$b} <=> $by_status{$a} } keys %by_status) {
    printf "%s : %d (%.1f%%)\n", $code, $by_status{$code}, 100 * $by_status{$code} / $total;
}

print "\n--- top 10 client IPs ---\n";
my $rank = 0;
for my $ip (sort { $by_ip{$b} <=> $by_ip{$a} } keys %by_ip) {
    last if ++$rank > 10;
    printf "%2d. %-20s %5d requests\n", $rank, $ip, $by_ip{$ip};
}

print "\n--- requests per hour-of-day ---\n";
for my $hour (sort { $a <=> $b } keys %by_hour) {
    printf "%s:00 %s %d\n", $hour, bar($by_hour{$hour}), $by_hour{$hour};
}

sub commify {
    my $n = reverse $_[0];
    $n =~ s/(\d{3})(?=\d)/$1,/g;
    return scalar reverse $n;
}

sub bar {
    my $count = shift;
    my $scale = 40;
    my $max = (sort { $by_hour{$b} <=> $by_hour{$a} } keys %by_hour)[0];
    my $len = $max ? int($scale * $count / $max) : 0;
    return '#' x $len;
}
