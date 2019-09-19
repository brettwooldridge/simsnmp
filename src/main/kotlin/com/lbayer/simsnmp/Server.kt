@file:Suppress("DEPRECATION")

package com.lbayer.simsnmp

import jdk.nashorn.api.scripting.NashornScriptEngineFactory
import org.apache.logging.log4j.LogManager
import org.snmp4j.CommandResponder
import org.snmp4j.CommandResponderEvent
import org.snmp4j.MessageException
import org.snmp4j.PDU
import org.snmp4j.Snmp
import org.snmp4j.mp.MPv3
import org.snmp4j.mp.MessageProcessingModel
import org.snmp4j.mp.SnmpConstants
import org.snmp4j.mp.StatusInformation
import org.snmp4j.security.SecurityModels
import org.snmp4j.security.SecurityProtocols
import org.snmp4j.security.USM
import org.snmp4j.smi.Address
import org.snmp4j.smi.Null
import org.snmp4j.smi.OID
import org.snmp4j.smi.OctetString
import org.snmp4j.smi.VariableBinding
import java.io.File
import java.io.FileReader
import java.io.IOException
import java.net.NetworkInterface
import java.net.SocketException
import java.util.*
import java.util.concurrent.Semaphore
import javax.script.Invocable
import javax.script.ScriptContext
import javax.script.ScriptException
import javax.script.SimpleScriptContext
import kotlin.collections.ArrayList
import kotlin.math.abs
import kotlin.system.exitProcess

class Server private constructor(props: Properties) : CommandResponder {

    private var snmp: Snmp? = null
    private val port = Integer.parseInt(props.getProperty("port", "161"))
    private val handlerScriptName = props.getProperty("handler", System.getProperty("handler", "agent.js"))
    private var handlerImpl: Invocable? = null
    private lateinit var loadedMibs: LinkedHashMap<String, DeviceMib>

    override fun <A : Address?> processPdu(event: CommandResponderEvent<A>) {
        try {
            if (LOGGER.isDebugEnabled) {
                LOGGER.debug("  Peer address: " + event.peerAddress + ", target address: " + (event.transportMapping as NettyUdpTransportMapping).localIp)
            }

            val reqPdu = event.pdu
            val repetitions = if (reqPdu.type != PDU.GETBULK) 1 else reqPdu.maxRepetitions

            val pdu = event.pdu.clone() as PDU
            pdu.type = PDU.RESPONSE

            // val source = (event.peerAddress as IpAddress).inetAddress.hostAddress
            val target = (event.transportMapping as NettyUdpTransportMapping).localIp

            val responseBindings = ArrayList<VariableBinding>()
            var variableBindings = reqPdu.variableBindings
            for (i in 0 until repetitions) {
                val newBindings = ArrayList<VariableBinding>()

                for (reqVar in variableBindings) {
                    val oid = reqVar.oid

                    val binding = getValue(reqPdu.type, target, oid)

                    if (binding != null) {
                        newBindings.add(binding)
                    } else {
                        pdu.errorStatus = SnmpConstants.SNMP_ERROR_NO_SUCH_NAME
                        if (event.messageProcessingModel == MessageProcessingModel.MPv1) {
                            pdu.errorIndex = PDU.noSuchName
                        } else {
                            pdu.errorIndex = 0
                            reqVar.variable = Null.noSuchObject
                        }
                        newBindings.add(reqVar)
                    }
                }

                if (reqPdu.type == PDU.GETBULK) {
                    variableBindings = newBindings
                }

                responseBindings.addAll(newBindings)
            }

            pdu.variableBindings = responseBindings

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
        } catch (e: Throwable) {
            LOGGER.error("Error handling request", e)
        }
    }

    private fun getValue(type: Any, target: String, oid: OID): VariableBinding? {
        return when (type) {
            PDU.GET -> {
                val variable = loadedMibs[target]?.let { deviceMib-> deviceMib.oids[oid] } ?: return null
                VariableBinding(oid, variable)
            }
            else    -> {
                loadedMibs[target] ?.let { deviceMib ->
                    val insertionIndex = abs(deviceMib.keys.binarySearch(oid) + 1)
                    if (insertionIndex < deviceMib.keys.size) {
                        val nextOid = deviceMib.keys[insertionIndex]
                        VariableBinding(nextOid, deviceMib.oids[nextOid])
                    }
                    else {
                        null
                    }
                }
            }
        }
    }

    @Suppress("unused")
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

    @Throws(IOException::class)
    private fun startServer() {
        LOGGER.info("=========== SNMP Simulator ===========")

        LOGGER.info("Loading device MIB response files...")
        loadedMibs = loadMibs()
        LOGGER.info("Loaded ${loadedMibs.size} response files.")

        val addresses = bindAddresses
        if (addresses.isEmpty()) {
            LOGGER.warn("No addresses to bind to")
            return
        }

        // handlerImpl = getHandlerScript();

        //        final Path path = Paths.get(handlerScriptName).getParent();
        //        path.register(watchService, StandardWatchEventKinds.ENTRY_MODIFY);

        LOGGER.info("Binding to ${addresses.size} addresses...")
        val transport = NettyUdpTransportMapping(addresses, port)
        LOGGER.info("Binding complete.")

        snmp = Snmp(transport)
        snmp!!.addCommandResponder(this)
        val usm = USM(SecurityProtocols.getInstance(), OctetString(MPv3.createLocalEngineID()), 0)
        SecurityModels.getInstance().addSecurityModel(usm)
        snmp!!.listen()

        LOGGER.info("Listening for SNMP requests.")

        val semaphore = Semaphore(0)
        semaphore.acquireUninterruptibly()
    }

    companion object {
        private val LOGGER = LogManager.getLogger(Server::class.java)

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

            try {
                val server = Server(props)
                server.startServer()
            } catch (e: Throwable) {
                LOGGER.error("Error running server", e)
            }

        }
    }
}
