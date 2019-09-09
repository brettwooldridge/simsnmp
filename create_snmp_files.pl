#!/usr/bin/env perl

use strict;
use warnings;

my $BASE_ADDR="10.129";

unless (-e "loadtest.snmp") {
    print "Error: cannot find loadtest.snmp file.\n";
    exit(-1);
}

foreach my $c (0 .. 19)
{
    foreach my $d (1 .. 254)
    {
        my $command = "cp loadtest.snmp $BASE_ADDR.$c.$d.snmp";
        print $command . "\n";
        print `$command`;
    }
}
