// This script is intended to run under the Nashorn JavaScript engine in Java 11, which supports many ES6 constructs.
// MOTE: Destructuring is not supported.

/*********************************************************
 * Global variables.
 */

const sessionMap = new java.util.concurrent.ConcurrentHashMap();  // used to hold getnext iterators per-device

const loadedValues = new java.util.concurrent.ConcurrentHashMap();  // ConcurrentHashMap<targetIP, LinkedHashMap<oid, value>>


/*****************************************************************************************************
 * Startup logic executed at script load time.  Load everything up-front to avoid delay in responses.
 */

{
    const snmpFiles = listSnmpFiles();   // *.snmp
    snmpFiles.forEach(function(file) {
        const name = file.substr(0, file.length - 5);    // eg. 10.129.0.1.snmp => 10.129.0.1
        loadSnmpValues(name);
    });
}


/*******************************************************************************************************************
 *                                                  PUBLIC API
 *******************************************************************************************************************/

/*********************************************************
 * SNMP GET operation.
 *
 * @param source the source IP address
 * @param target the target IP address
 * @param oid the OID as a string
 * @returns the binding or null
 */
function get(source, target, oid) {
    LOGGER.debug("get: " + source + "->" + target + " " + oid);
    const value = doGet(source, target, oid);
    LOGGER.debug("response: " + value);
    return value;
}

// noinspection JSUnusedGlobalSymbols
/*********************************************************
 * SNMP GETNEXT operation.
 *
 * @param source the source IP address
 * @param target the target IP address
 * @param oid the OID as a string
 * @returns the binding or null
 */
function getnext(source, target, oid) {
    // if (LOGGER.isDebugEnabled()) LOGGER.debug("getnext: " + source + "->" + target + "   oid: " + oid);

    let new_oid;
    if (oid === "1.3.6.1.2.1.1") {
        new_oid = "1.3.6.1.2.1.1.1.0";
    } else if (oid === "1.3.6.1.2.1.1.1.0") {
        new_oid = "1.3.6.1.2.1.1.2.0";
    } else if (oid === "1.3.6.1.2.1.1.2.0") {
        new_oid = "1.3.6.1.2.1.1.5.0";
    } else {
        const valueIterator = getIterator(source, target, oid);
        if (valueIterator == null) return null;

        if (!valueIterator.hasNext()) {
            // if (LOGGER.isDebugEnabled()) LOGGER.debug("Iterator exhausted.  Removing.");
            sessionMap.remove(source + target);
            return null;
        }

        let value = valueIterator.next();

        // if (LOGGER.isDebugEnabled()) LOGGER.debug("response: " + value);
        return value.getValue();
    }

    // if (LOGGER.isDebugEnabled()) LOGGER.debug("getnext: " + oid + " ==> " + new_oid);
    return get(source, target, new_oid);
}

function getbulk(source, target, oid, repetitions) {
    const valueIterator = getIterator(source, target, oid);
    if (valueIterator == null) return null;

    const bindings = new java.util.ArrayList();
    for (let i = 0; i < repetitions && valueIterator.hasNext(); i++) {
        let value = valueIterator.next();
        bindings.add(value.getValue());
    }

    if (!valueIterator.hasNext()) {
        // if (LOGGER.isDebugEnabled()) LOGGER.debug("Iterator exhausted.  Removing.");
        sessionMap.remove(source + target);
    }

    return bindings;
}


/*******************************************************************************************************************
 *                                                  INTERNAL API
 *******************************************************************************************************************/

function doGet(source, target, oid) {
    let snmpValues = loadedValues.get(target);
    if (snmpValues != null) {
        return snmpValues['.' + oid];
    }
    else {
        return null;
    }
}

function getIterator(source, target, oid) {
    return sessionMap.computeIfAbsent(source + target, function (ignore) {
        let snmpValues = loadedValues.get(target);
        // if (LOGGER.isDebugEnabled()) LOGGER.debug("snmpValues=" + snmpValues);
        if (snmpValues == null) {
            return null;
        }

        // Iterator of VariableBindinds
        const iterator = new java.util.ArrayList(snmpValues.entrySet()).listIterator();
        while (iterator.hasNext()) {
            const entry = iterator.next();
            if (entry.getKey().startsWith('.' + oid)) {
                iterator.previous();
                break;
            }
        }
        return (iterator.hasNext() ? iterator : new java.util.ArrayList(snmpValues.entrySet()).listIterator());
    });
}

function loadSnmpValues(target) {
    const filename = target + ".snmp";
    if (!new_file(filename).isFile()) {
        return null;
    }

    let prevKey;
    const result = new java.util.LinkedHashMap();
    readFile(filename)
        .forEach(function(line) {
            const keyValue = line.split(' = ', 2);
            let key = keyValue[0];
            let value = keyValue.length > 1 ? keyValue[1] : null;

            if (!value) {  // text line continuation
                // key exists from previous loop iteration
                const prevVariable = result.get(prevKey);
                const octet = prevVariable.getVariable();
                octet.append(org.snmp4j.smi.OctetString.fromString(key, ' ', 16));
            } else {
                if (value.startsWith('INTEGER: ')) {
                    value = getBinding(key, new org.snmp4j.smi.Integer32(value.substring(9)));
                } else if (value.startsWith('Counter32: ')) {
                    value = getBinding(key, new org.snmp4j.smi.Counter32(value.substring(11)));
                } else if (value.startsWith('Counter64: ')) {
                    value = getBinding(key, new org.snmp4j.smi.Counter64(value.substring(11)));
                } else if (value.startsWith('Hex-STRING: ')) {
                    value = getBinding(key, org.snmp4j.smi.OctetString.fromString(value.substring(12), ' ', 16));
                } else if (value === "\"\"") {
                    value = getBinding(key, new org.snmp4j.smi.OctetString(""));
                } else if (value.startsWith('Timeticks: ')) {
                    const regex = /\((\d+)\)/gm;
                    const result = regex.exec(value);
                    value = getBinding(key, new org.snmp4j.smi.TimeTicks(java.lang.Long.parseLong(result[1])));
                } else if (value.startsWith('OID: ')) {
                    value = value.substring(5);
                    if (value.startsWith('SNMPv2-SMI::enterprises')) {
                        value = '.1.3.6.1.4.1' + value.substring(23);
                    }
                    value = getBinding(key, new org.snmp4j.smi.OID(value));
                }

                result.put(key, value);
                prevKey = key;
            }
        });

    loadedValues.put(target, result);
    return result;
}

function getBinding(oid, variable) {
    return new org.snmp4j.smi.VariableBinding(new org.snmp4j.smi.OID(oid), variable);
}

function readFile(name) {
    return Java.from(java.nio.file.Files.readAllLines(java.nio.file.Paths.get(name), java.nio.charset.Charset.forName("UTF-8")));
}

function new_file(name) {
    return new java.io.File(name);
}

function listSnmpFiles() {
    const dir = new_file(".");
    const files = dir["list(java.io.FilenameFilter)"](function (dir, name) {
        return name.match("\.snmp$");
    });

    return Java.from(files);
}
