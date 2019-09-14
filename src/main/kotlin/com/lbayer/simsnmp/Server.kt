@file:Suppress("DEPRECATION")

package com.lbayer.simsnmp

import jdk.nashorn.api.scripting.NashornScriptEngineFactory
import org.apache.log4j.ConsoleAppender
import org.apache.log4j.Level
import org.apache.log4j.Logger
import org.apache.log4j.PatternLayout
import org.snmp4j.*
import org.snmp4j.mp.MPv3
import org.snmp4j.mp.MessageProcessingModel
import org.snmp4j.mp.SnmpConstants
import org.snmp4j.mp.StatusInformation
import org.snmp4j.security.SecurityModels
import org.snmp4j.security.SecurityProtocols
import org.snmp4j.security.USM
import org.snmp4j.smi.*
import java.io.File
import java.io.FileReader
import java.io.IOException
import java.net.NetworkInterface
import java.net.SocketException
import java.nio.charset.StandardCharsets
import java.nio.file.*
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Semaphore
import java.util.concurrent.atomic.AtomicReference
import java.util.regex.Pattern
import javax.script.Invocable
import javax.script.ScriptContext
import javax.script.ScriptException
import javax.script.SimpleScriptContext
import kotlin.system.exitProcess

class Server private constructor(props: Properties) : CommandResponder {

    private var snmp: Snmp? = null
    private val port = Integer.parseInt(props.getProperty("port", "161"))
    private val handlerScriptName = props.getProperty("handler", System.getProperty("handler", "agent.js"))
    private var handlerImpl: Invocable? = null
    private val watchService: WatchService? = null
    private val loadedMibs = ConcurrentHashMap<String, LinkedHashMap<String, Any>>()

    private val handlerScript: Invocable?
        @Synchronized get() = try {
            FileReader(handlerScriptName).use { r ->
                val ctx = SimpleScriptContext()
                val bindings = ctx.getBindings(ScriptContext.ENGINE_SCOPE)
                bindings["LOGGER"] = LOGGER

                val engine = NashornScriptEngineFactory().getScriptEngine("--language=es6")

                LOGGER.info("Loading handler script $handlerScriptName")

                engine.context = ctx
                engine.eval(r)

                handlerImpl = engine as Invocable
                return handlerImpl
            }
        } catch (e: ScriptException) {
            throw RuntimeException(e)
        } catch (e: IOException) {
            throw RuntimeException(e)
        }

    private val bindAddresses: List<String>
        @Throws(SocketException::class)
        get() {
            val addresses = ArrayList<String>()

            val ifaces = NetworkInterface.getNetworkInterfaces()
            while (ifaces.hasMoreElements()) {
                val inetAddresses = ifaces.nextElement().inetAddresses
                while (inetAddresses.hasMoreElements()) {
                    val addr = inetAddresses.nextElement().hostAddress
                    addresses.add(addr)
                    LOGGER.debug("Added listen address: $addr")
                }
            }

            return addresses
        }

    private fun getValue(source: String, target: String?, type: Int, oid: OID, reqID: Integer32, repetitions: Int): Array<VariableBinding>? {
        if (LOGGER.isDebugEnabled) LOGGER.debug("getValue(source=$source, target=$target, oid=$oid)")

        try {
            // Check the watch service to see whether the script has changed (and reload)
            var key: WatchKey? = watchService!!.poll()
            while (key != null) {
                for (event in key.pollEvents()) {
                    val path = event.context() as Path
                    if (event.kind() !== StandardWatchEventKinds.OVERFLOW && path.endsWith(handlerScriptName)) {
                        handlerImpl = handlerScript
                        break
                    }
                }
                key.reset()
                key = watchService.poll()
            }

            val method = when (type) {
                PDU.GET -> "get"

                PDU.GETNEXT -> "getnext"

                PDU.GETBULK -> "getbulk"
                else -> return null
            }

            val binding = handlerImpl!!.invokeFunction(method, source, target, oid.toDottedString(), reqID, repetitions)
            if (binding != null && LOGGER.isDebugEnabled) LOGGER.debug("Invoked " + method + " with result class " + binding.javaClass + " and value: " + binding)

            @Suppress("UNCHECKED_CAST")
            return if (binding is VariableBinding) {
                Array<VariableBinding>(1) { binding }
            } else {
                binding as Array<VariableBinding>
            }
        } catch (e: NoSuchMethodException) {
            LOGGER.error("Error executing handler script", e)
            return null
        } catch (e: ScriptException) {
            LOGGER.error("Error executing handler script", e)
            return null
        }

    }

    override fun processPdu(event: CommandResponderEvent) {
        try {
            if (LOGGER.isDebugEnabled) {
                LOGGER.debug("  Peer address: " + event.peerAddress + ", target address: " + (event.transportMapping as NettyUdpTransportMapping).localIp)
            }

            val reqPdu = event.pdu
            val reqID = reqPdu.requestID
            val repetitions = if (reqPdu is PDUv1) 0 else reqPdu.maxRepetitions
            handleGet(event, reqPdu, reqID, repetitions)
        } catch (e: Throwable) {
            LOGGER.error("Error handling request", e)
        }

    }

    private fun handleGet(event: CommandResponderEvent, reqPdu: PDU, reqID: Integer32, repetitions: Int) {
        val pdu = event.pdu.clone() as PDU
        pdu.type = PDU.RESPONSE

        val newVariables = ArrayList<VariableBinding>()

        val source = (event.peerAddress as IpAddress).inetAddress.hostAddress
        val target = (event.transportMapping as NettyUdpTransportMapping).localIp
        for (reqVar in reqPdu.variableBindings) {
            val oid = reqVar.oid

            val bindings = getValue(source, target, reqPdu.type, oid, reqID, repetitions)
            if (bindings == null) {
                pdu.errorStatus = SnmpConstants.SNMP_ERROR_NO_SUCH_NAME
                if (event.messageProcessingModel == MessageProcessingModel.MPv1) {
                    pdu.errorIndex = PDU.noSuchName
                } else {
                    pdu.errorIndex = 0
                    reqVar.variable = Null.noSuchObject
                }
                newVariables.add(reqVar)
            } else {
                Collections.addAll(newVariables, *bindings)
            }
        }

        pdu.setVariableBindings(newVariables)

        try {
            snmp!!.messageDispatcher.returnResponsePdu(
                    event.messageProcessingModel,
                    event.securityModel,
                    event.securityName,
                    event.securityLevel,
                    pdu,
                    event.maxSizeResponsePDU,
                    event.stateReference,
                    StatusInformation())
        } catch (e: MessageException) {
            e.printStackTrace()
        }

    }

    private class Table {
        var tableRegex: Pattern? = null

        val tablesRows = mutableMapOf<String, TableRow>()

        class TableRow {
            val columns = mutableMapOf<String, VariableBinding>()
        }
    }

    @Throws(IOException::class)
    private fun loadMibs() {

        val tableRef = AtomicReference<Table>()
        Files.list(Paths.get("."))
                .filter { path -> path.toString().endsWith(".snmp") }
                .forEach { path ->
                    try {
                        tableRef.set(null)
                        val ipAddress = path.toFile().name
                        val currBindingRef = AtomicReference<VariableBinding>()

                        Files.lines(path, StandardCharsets.UTF_8)
                                .filter { line -> !line.startsWith("#") }
                                .forEach loop@ { line ->
                                    val map = loadedMibs.computeIfAbsent(ipAddress) { LinkedHashMap() }

                                    val matcher = TABLE_REGEX.matcher(line)
                                    if (line.startsWith("table ") && matcher.find()) {
                                        val prefix = matcher.group(1)
                                        val colCardinality = countChars(matcher.group(2), 'c')
                                        val rowCardinality = countChars(matcher.group(3), 'i')
                                        val table = Table()
                                        table.tableRegex = Pattern.compile(String.format("$prefix((?:\\.[.\\d]+){%d})((?:\\.[.\\d]+){%d}) =", colCardinality, rowCardinality))
                                        tableRef.set(table)

                                        map[prefix] = table
                                        return@loop
                                    }

                                    val keyValue = line.split(" = ".toRegex(), 2).toTypedArray()

                                    val table = tableRef.get()
                                    if (table != null && keyValue.size == 2) {
                                        val matcher2 = table.tableRegex!!.matcher(line)
                                        if (matcher2.find()) {
                                            val colIndex = matcher2.group(1)
                                            val rowIndex = matcher2.group(2)

                                            val row = table.tablesRows.computeIfAbsent(rowIndex) { Table.TableRow() }
                                            val column = row.columns.computeIfPresent(colIndex) { _, v -> createBinding(line, v) }
                                            if (column == null) {
                                                row.columns[colIndex] = createBinding(line, null)
                                            }

                                            currBindingRef.set(row.columns[colIndex])
                                            return@loop
                                        } else {
                                            tableRef.set(null)
                                            // fall thru
                                        }
                                    }

                                    val key = keyValue[0]
                                    val value = if (keyValue.size > 1) keyValue[1] else null

                                    if (value == null && currBindingRef.get() != null) {
                                        val binding = currBindingRef.get()
                                        createBinding(line, binding)
                                    } else {
                                        val binding = createBinding(line, null)
                                        map[key] = binding
                                        currBindingRef.set(binding)
                                    }
                                }
                    } catch (e: IOException) {
                        e.printStackTrace()
                    }
                }
    }

    private fun createBinding(line: String, existing: VariableBinding?): VariableBinding {
        val keyValue = line.split(" = ".toRegex(), 2).toTypedArray()
        val key = keyValue[0]
        var value: String? = if (keyValue.size > 1) keyValue[1] else null

        return if (value == null && existing != null) {  // text line continuation
            // key exists from previous loop iteration
            val octet = existing.variable as OctetString
            octet.append(OctetString.fromString(key, ' ', 16))
            return existing
        } else if (value == null) {
            throw java.lang.IllegalStateException("Invalid line: $line")
        } else if (value.startsWith("INTEGER: ")) {
            VariableBinding(OID(key), Integer32(Integer.parseInt(value.substring(9))))
        } else if (value.startsWith("Counter32: ")) {
            VariableBinding(OID(key), Counter32(java.lang.Long.parseLong(value.substring(11))))
        } else if (value.startsWith("Counter64: ")) {
            VariableBinding(OID(key), Counter64(java.lang.Long.parseLong(value.substring(11))))
        } else if (value.startsWith("Gauge32: ")) {
            VariableBinding(OID(key), Counter32(java.lang.Long.parseLong(value.substring(11))))
        } else if (value.startsWith("Hex-STRING: ")) {
            VariableBinding(OID(key), OctetString.fromString(value.substring(12), ' ', 16))
        } else if (value.startsWith("Timeticks: ")) {
            val regex = Pattern.compile("\\((\\d+)\\)").matcher(value)
            check(regex.find()) { "No match for: " + value!! }
            VariableBinding(OID(key), TimeTicks(java.lang.Long.parseLong(regex.group(1))))
        } else if (value.startsWith("OID: ")) {
            value = value.substring(5)
            if (value.startsWith("SNMPv2-SMI::enterprises")) {
                value = ".1.3.6.1.4.1" + value.substring(23)
            }
            VariableBinding(OID(key), OID(value))
        } else if (!value.startsWith("JS: ")) { // Javascript
            throw IllegalStateException("Javascript values are not yet implemented")
        } else if (value == "\"\"") {
            VariableBinding(OID(key), OctetString(""))
        } else {
            throw IllegalStateException("Invalid line: $line")
        }
    }

    private fun countChars(str: String, c: Char): Int {
        return str.chars().filter { ch -> ch == c.toInt() }.count().toInt()
    }

    @Throws(IOException::class)
    private fun startServer() {
        LOGGER.info("Starting SNMP server")

        loadMibs()

        val addresses = bindAddresses
        if (addresses.isEmpty()) {
            LOGGER.warn("No addresses to bind to")
            return
        }

        // handlerImpl = getHandlerScript();

        //        watchService = FileSystems.getDefault().newWatchService();
        //        final Path path = Paths.get(handlerScriptName).getParent();
        //        path.register(watchService, StandardWatchEventKinds.ENTRY_MODIFY);

        val transport = NettyUdpTransportMapping(addresses, port)

        snmp = Snmp(transport)
        snmp!!.addCommandResponder(this)
        val usm = USM(SecurityProtocols.getInstance(), OctetString(MPv3.createLocalEngineID()), 0)
        SecurityModels.getInstance().addSecurityModel(usm)
        snmp!!.listen()

        LOGGER.info("Listening for SNMP requests")

        val semaphore = Semaphore(0)
        semaphore.acquireUninterruptibly()
    }

    companion object {
        private val LOGGER = Logger.getLogger(Server::class.java)

        @JvmStatic
        fun main(args: Array<String>) {
            var config = "agent.conf"
            val listIterator = listOf(*args).listIterator()
            while (listIterator.hasNext()) {
                val next = listIterator.next()
                if (next == "-c") {
                    if (!listIterator.hasNext()) {
                        System.err.println("Invalid arguments: No configuration specified")
                        exitProcess(1)
                    }

                    config = listIterator.next()
                    if (!File(config).isFile) {
                        System.err.println("Invalid arguments: No such file: $config")
                        exitProcess(2)
                    }
                }
            }

            val props = Properties()

            val file = File(config)
            if (file.isFile) {
                try {
                    FileReader(file).use { reader -> props.load(reader) }
                } catch (e: IOException) {
                    System.err.println("Configuration error: Error loading file: $config")
                    System.err.println(e.message)
                    exitProcess(3)
                }

            }

            val rootLogger = Logger.getRootLogger()

            val consoleAppender = ConsoleAppender(PatternLayout("%d{HH:mm:ss,SSS} [%-25t] %-5p - %m%n"))
            rootLogger.addAppender(consoleAppender)
            consoleAppender.target = "System.err"
            consoleAppender.threshold = Level.INFO
            consoleAppender.activateOptions()

            try {
                val server = Server(props)
                server.startServer()
            } catch (e: Throwable) {
                LOGGER.error("Error running server", e)
            }

        }

        private val TABLE_REGEX = Pattern.compile("table ([.\\d]+)\\.([.c]+)\\.([.i]+)", Pattern.DOTALL)
    }
}
