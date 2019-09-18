package com.lbayer.simsnmp

import org.snmp4j.smi.AbstractVariable
import org.snmp4j.smi.Counter32
import org.snmp4j.smi.Counter64
import org.snmp4j.smi.Gauge32
import org.snmp4j.smi.Integer32
import org.snmp4j.smi.OID
import org.snmp4j.smi.OctetString
import org.snmp4j.smi.TimeTicks
import org.snmp4j.smi.UnsignedInteger32
import org.snmp4j.smi.Variable
import org.snmp4j.smi.VariantVariable
import org.snmp4j.smi.VariantVariableCallback
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Paths
import java.util.*
import java.util.concurrent.ThreadLocalRandom
import java.util.concurrent.atomic.AtomicReference
import kotlin.collections.LinkedHashMap
import kotlin.math.max
import kotlin.math.min

private val autoRegex = Regex("""auto\((\d+),\s*(\d+)\)""")

internal class DeviceMib(val oids: SortedMap<OID, Variable>) {
    val keys = oids.keys.toList()
}

@Throws(IOException::class)
internal fun loadMibs(): LinkedHashMap<String, DeviceMib> {
    val loadedMibs = LinkedHashMap<String, DeviceMib>()

    Files.list(Paths.get("."))
        .filter { path -> path.toString().endsWith(".snmp") }
        .forEach { path ->
            try {
                val currBindingRef = AtomicReference<Variable>()
                val ipAddress = path.toFile().name.substringBeforeLast('.')
                val oids = mutableMapOf<OID, Variable>()

                Files.lines(path, StandardCharsets.UTF_8)
                    .filter { line -> !line.startsWith("#") }
                    .forEach { line ->
                        val keyValue = line.split(" = ".toRegex(), 2).toTypedArray()
                        val key = keyValue[0]
                        val value = if (keyValue.size > 1) keyValue[1] else null

                        if (value == null && currBindingRef.get() != null) {
                            val binding = currBindingRef.get()
                            createBinding(line, binding)
                        } else {
                            val variable = createBinding(line, null)
                            oids[OID(key)] = variable
                            currBindingRef.set(variable)
                        }
                    }

                loadedMibs.computeIfAbsent(ipAddress) { DeviceMib(oids.toSortedMap()) }
            } catch (e: IOException) {
                e.printStackTrace()
            }
        }
    return loadedMibs
}

private fun createBinding(line: String, existing: Variable?): Variable {
    val keyValue = line.split(" = ".toRegex(), 2).toTypedArray()
    val key = keyValue[0]
    val value: String? = if (keyValue.size > 1) keyValue[1] else null

    if (value == null && existing != null) {  // text line continuation
        // key exists from previous loop iteration
        val octet = existing as OctetString
        octet.append(OctetString.fromString(key, ' ', 16))
        return existing
    }
    else if (value == null) {
        throw java.lang.IllegalStateException("Invalid line: $line")
    } else if (value.startsWith("INTEGER: ")) {
        return Integer32(value.substring(9).toInt())
    } else if (value.startsWith("Counter32: ")) {
        return createCounter<Counter32>(value.substring(11).trim())
    } else if (value.startsWith("Counter64: ")) {
        return createCounter<Counter64>(value.substring(11).trim())
    } else if (value.startsWith("Unsigned32: ")) {
        return UnsignedInteger32(value.substring(12).toLong())
    } else if (value.startsWith("Gauge32: ")) {
        return createGauge(value.substring(9))
    } else if (value.startsWith("Hex-STRING: ")) {
        return OctetString.fromString(value.substring(12), ' ', 16)
    } else if (value.startsWith("Timeticks: ")) {
        val result = Regex("""\((\d+)\)""").find(value)!!
        return TimeTicks(result.groupValues[1].toLong())
    } else if (value.startsWith("OID: ")) {
        return OID(value.substring(5))
    } else if (value == "\"\"") {
        return OctetString("")
    }
    else if (value.startsWith("JS: ")) { // Javascript
        throw IllegalStateException("Javascript values are not yet implemented: $line")
    } else {
        throw IllegalStateException("Invalid line: $line")
    }
}

private inline fun <reified T> createCounter(value: String): AbstractVariable {
    return if (value.startsWith("auto")) {
        val (_, initial, increment) = autoRegex.find(value)!!.groupValues
        VariantVariable(T::class.java.getDeclaredConstructor(java.lang.Long.TYPE).newInstance(initial.toLong()) as Variable, object: VariantVariableCallback {
            override fun updateVariable(wrapper: VariantVariable) {
                when (val variable = wrapper.variable) {
                    is Counter32 -> variable.increment(increment.toLong())
                    is Counter64 -> variable.increment(increment.toLong())
                }
            }

            override fun variableUpdated(wrapper: VariantVariable?) {}
        })
    }
    else {
        when (T::class.java.name.substringAfterLast('.')) {
            "Counter32" -> Counter32(value.toLong())
            else        -> Counter64(value.toLong())
        }
    }
}

private fun createGauge(value: String): AbstractVariable {
    return if (value.startsWith("auto")) {
        val (_, minStr, maxStr) = autoRegex.find(value)!!.groupValues
        val min = minStr.toLong()
        val max = maxStr.toLong()
        val tenPct = (max.toDouble() * 0.1).toLong()

        VariantVariable(Gauge32(max / 2), object: VariantVariableCallback {
            override fun updateVariable(wrapper: VariantVariable) {
                val newValue = max(min, min(max, wrapper.variable.toLong() + ThreadLocalRandom.current().nextLong(-tenPct, tenPct)))
                wrapper.setValue(newValue)
            }

            override fun variableUpdated(wrapper: VariantVariable?) {}
        })
    }
    else {
        Gauge32(value.toLong())
    }
}
