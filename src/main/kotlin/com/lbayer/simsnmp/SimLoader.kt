@file:Suppress("DEPRECATION")

package com.lbayer.simsnmp

import jdk.nashorn.api.scripting.NashornScriptEngineFactory
import org.snmp4j.smi.*
import java.io.FileReader
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Paths
import java.util.*
import java.util.concurrent.ThreadLocalRandom
import java.util.concurrent.atomic.AtomicReference
import javax.script.*
import kotlin.collections.LinkedHashMap
import kotlin.math.max
import kotlin.math.min

private val autoRegex = Regex("""auto\((\d+),\s*(\d+)\)""")
private val jsFunc1Regex = Regex("""(\w+)\((([^,]+,?\s*)*)\)""")

private val jsEngine = object : ThreadLocal<Invocable>() {
    override fun initialValue(): Invocable {
        val script = System.getProperty("handler", "agent.js")
        return getHandlerScript(script)
    }
}

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
        val (_, initialStr, incrementStr) = autoRegex.find(value)!!.groupValues
        val increment = incrementStr.toLong()
        val twentyPct = (increment.toDouble() * 0.2).toLong()

        val counter = T::class.java.getDeclaredConstructor(java.lang.Long.TYPE).newInstance(initialStr.toLong()) as Variable
        VariantVariable(counter, object: VariantVariableCallback {
            override fun updateVariable(wrapper: VariantVariable) {
                when (val variable = wrapper.variable) {
                    is Counter32 -> variable.increment(increment - ThreadLocalRandom.current().nextLong(-twentyPct, twentyPct))
                    is Counter64 -> variable.increment(increment - ThreadLocalRandom.current().nextLong(-twentyPct, twentyPct))
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

private fun createJavascript(value: String): AbstractVariable {
    val (funcName, params) = jsFunc1Regex.find(value)!!.groupValues
    val invokeFuncSig = """$funcName(variable${if (params.isBlank()) "" else ", " + params})"""
    return VariantVariable(Gauge32(), object : VariantVariableCallback {
        override fun updateVariable(wrapper: VariantVariable?) {
            jsEngine.get().invokeMethod(null, invokeFuncSig, wrapper)
        }

        override fun variableUpdated(p0: VariantVariable?) {}
    })
}

@Suppress("unused")
internal fun getHandlerScript(handlerScriptName: String): Invocable {
    try {
        Server.LOGGER.info("Loading handler script $handlerScriptName")
        FileReader(handlerScriptName).use { r ->
            val ctx = SimpleScriptContext()
            val bindings = ctx.getBindings(ScriptContext.ENGINE_SCOPE)
            bindings["LOGGER"] = Server.LOGGER

            val engine = NashornScriptEngineFactory().getScriptEngine("--language=es6") // "--global-per-engine"
            engine.context = ctx

            val compilable = engine as Compilable
            val compiled = compilable.compile(r)
            compiled.eval()


            // engine.eval(r)

            return engine as Invocable
        }
    } catch (e: ScriptException) {
        throw RuntimeException(e)
    } catch (e: IOException) {
        throw RuntimeException(e)
    }
}
