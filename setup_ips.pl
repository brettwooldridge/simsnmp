#!/usr/bin/env perl

use strict;
use warnings;

my $BASE_ADDR="10.129";

die "Must be run as root\n" if ($<);

foreach my $c (0 .. 19)
{
    foreach my $d (1 .. 254)
    {
    my $command = "ip addr add $BASE_ADDR.$c.$d/24 dev eth0";
    print $command . "\n";
    print `$command`;
    }
}
