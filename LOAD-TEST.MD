## Generating .snmp files
Device files have naming of the format ``10.129.0.1.snmp``, generalized as ``<ip>.snmp``.

Use the following format command when generating SNMP values for device files:
```shell
snmpwalk -c public -Ih -Onex 10.0.0.250 ifTable
```
In particular, the important parts to note are the inclusion of ``-Ih`` and ``-Onex`` switches.  The ``-Ih``
disables display hints, and in combination with the ``-Ox`` switch ensures that strings are printed as
hexadecimal values.


<p>&nbsp;<p></p>

## Creating hundreds/thousands of device files

The ``create_snmp_files.pl`` script can be used to create device files for a large number of devices.
The script copies a file named ``loadtest.snmp`` to create device files fittig the naming convention above.

You can edit this file to alter the IP address range.

An abbreviated form of this file is:
```perl
my $BASE_ADDR="10.129";

foreach my $c (0 .. 19)
{
    foreach my $d (1 .. 254)
    {
        my $command = "cp loadtest.snmp $BASE_ADDR.$c.$d.snmp";
        print $command . "\n";
        print `$command`;
    }
}
```
Using the ``$BASE_ADDR`` value of ``10.129``, the script generates ``.snmp`` files for the addresses *10.129.0.1 - 10.129.19.254*.

To run this script, execute the command:
```shell
bash$ ./create_snmp_files.pl
```

<p>&nbsp;<p></p>

## Creating hundreds/thousands of Interfaces on Linux

The ``setup_ips.pl`` script can be used to create a large number of interfaces on Linux.

An abbreviated form of this file is:
```perl
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
```
This script can be edited to suit your purposes.  Unmodified, this script will create interfaces with IP addresses
in the range of 10.129.0.1 - 10.129.19.254 (5080 interfaces).

To run this script, execute the command:
```shell
bash$ ./setup_ips.pl
```
