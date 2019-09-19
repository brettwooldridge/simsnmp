# simsnmp

## Build

```
mvn clean package assembly:single
```

Result file is ``./target/simsnmp-all.jar``.

## Execution

For execution you need only the ``simsnmp-all.jar``, and Java 11 installed.  However, the following scripts in the root
of this project are useful:

### setup_ips.sh
This script is use to create 5080 interfaces on Linux, in the range 10.129.0.1-10.129.19.254.  By editing this file,
you can control the range and number of interfaces created.


### loadtest-sim.sh
This script is used to execute the simulator, and provides several important parameters to tthe invocation of Java.
```
./loadtest-sim.sh
```

### loadtest.snmp
This file serves as an example of an SNMP response file.  See below for more about SNMP response files.

-----------------------------------------------------------------
## SNMP Response Files
The simulator will load all files in the local directory that end with the ``.snmp`` extension.  Additionally, the
file name itself must be an IP address.  For example, ``10.129.0.1.snmp`` or ``192.168.90.10.snmp``.

The easiest way to produce a response file is by performing an SNMP walk of an actual device.  For example:
```shell
$ snmpwalk -r 0 -v 2c -On -c public 10.0.0.250 .1.3.6.1.2.1.2.2
.1.3.6.1.2.1.2.2.1.1.1 = INTEGER: 1
.1.3.6.1.2.1.2.2.1.1.2 = INTEGER: 2
.1.3.6.1.2.1.2.2.1.1.3 = INTEGER: 3
.1.3.6.1.2.1.2.2.1.1.4 = INTEGER: 4
.1.3.6.1.2.1.2.2.1.1.5 = INTEGER: 5
.1.3.6.1.2.1.2.2.1.1.6 = INTEGER: 6
.1.3.6.1.2.1.2.2.1.1.7 = INTEGER: 7
.1.3.6.1.2.1.2.2.1.1.8 = INTEGER: 8
.1.3.6.1.2.1.2.2.1.2.1 = STRING: Embedded-Service-Engine0/0
.1.3.6.1.2.1.2.2.1.2.2 = STRING: GigabitEthernet0/0
...
```
Using redirection to a file is probably simplest:
```
$ snmpwalk -r 0 -v 2c -On -c public 10.0.0.250 .1.3.6.1.2.1.2.2 > response.snmp
```
### Variation
The simulator provides two mechanisms for generating variation in the SNMP responses.

#### Counter32/64
The first variation generator can be applied to the Counter32 and Counter64 types.

Here is an original line of output from an snmpwalk for the ``ifInOctets`` OID (.1.3.6.1.2.1.2.2.1.10.2) on a local
device:
```
.1.3.6.1.2.1.2.2.1.10.2 = Counter32: 320970
``` 
Because it would be desirable for this counter to increase every time it is polled, simulating in this case network
traffic, this line in a response file can be modified like so:
```
.1.3.6.1.2.1.2.2.1.10.2 = Counter32: auto(0,123456)
```
> The ``auto()`` directive for counter types has the following form: ``auto(intial, increment)``.

The counter will start out at the initial value, and each time polled will increase by *approximately* the specified increment.
I say *approximately* because in order to produce a realistic traffic pattern, rather then what appears to be a perfectly
constant data rate, some random variation *around* the ``increment`` value is used.


#### Gauge32

The first variation generator can be applied to the Gauge32 type.

Here is an original line of output from an snmpwalk for the ``ciscoEnvMonTemperatureStatusValue`` OID
(	1.3.6.1.4.1.9.9.13.1.3.1.3) on a local device:
```
.1.3.6.1.4.1.9.9.13.1.3.1.3.1 = Gauge32: 31
``` 
In this case, the ``31`` is a temperature in celsius.  If this entry were in our response file, we could modify it
like so to generate variant values:
```
.1.3.6.1.4.1.9.9.13.1.3.1.3.1 = Gauge32: auto(10,70)
```
>The ``auto()`` directive for the gauge type has the following form: ``auto(min, max)``.

The guage will start out with an initial value of ``max / 2``, and upon each SNMP polling operation, the guage value 
will be perturbed either downwards or upwards by a random amount not exceeding 10% of the ``max`` value.  Of course,
the value resulting value will always be kept within the min/max bounds.
