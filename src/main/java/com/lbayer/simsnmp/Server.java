package com.lbayer.simsnmp;

import jdk.nashorn.api.scripting.NashornScriptEngineFactory;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.snmp4j.*;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.MessageProcessingModel;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.mp.StatusInformation;
import org.snmp4j.security.SecurityModels;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.USM;
import org.snmp4j.smi.*;

import javax.script.Invocable;
import javax.script.ScriptContext;
import javax.script.ScriptException;
import javax.script.SimpleScriptContext;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

public class Server implements CommandResponder
{
    private static final Logger LOGGER = Logger.getLogger(Server.class);

    private Snmp snmp;
    private int port;
    private String handlerScriptName;
    private Invocable handlerImpl;
    private WatchService watchService;
    private ConcurrentHashMap<String, LinkedHashMap<String, Object>> loadedMibs;

    private Server(Properties props)
    {
        this.port = Integer.parseInt(props.getProperty("port", "161"));
        this.handlerScriptName = props.getProperty("handler", System.getProperty("handler", "agent.js"));
        this.loadedMibs = new ConcurrentHashMap<>();
    }

    public static void main(String[] args)
    {
        String config = "agent.conf";
        var listIterator = Arrays.asList(args).listIterator();
        while (listIterator.hasNext())
        {
            String next = listIterator.next();
            if (next.equals("-c"))
            {
                if (!listIterator.hasNext())
                {
                    System.err.println("Invalid arguments: No configuration specified");
                    System.exit(1);
                    return;
                }

                config = listIterator.next();
                if (!new File(config).isFile())
                {
                    System.err.println("Invalid arguments: No such file: " + config);
                    System.exit(2);
                    return;
                }
            }
        }

        var props = new Properties();

        var file = new File(config);
        if (file.isFile())
        {
            try (var reader = new FileReader(file))
            {
                props.load(reader);
            }
            catch (IOException e)
            {
                System.err.println("Configuration error: Error loading file: " + config);
                System.err.println(e.getMessage());
                System.exit(3);
                return;
            }
        }

        Logger rootLogger = Logger.getRootLogger();

        var consoleAppender = new ConsoleAppender(new PatternLayout("%d{HH:mm:ss,SSS} [%-25t] %-5p - %m%n"));
        rootLogger.addAppender(consoleAppender);
        consoleAppender.setTarget("System.err");
        consoleAppender.setThreshold(Level.INFO);
        consoleAppender.activateOptions();

        try
        {
            var server = new Server(props);
            server.startServer();
        }
        catch (Throwable e)
        {
            LOGGER.error("Error running server", e);
        }
    }

    private synchronized Invocable getHandlerScript()
    {
        try (var r = new FileReader(handlerScriptName)) {
            var ctx = new SimpleScriptContext();
            var bindings = ctx.getBindings(ScriptContext.ENGINE_SCOPE);
            bindings.put("LOGGER", LOGGER);

            var engine = new NashornScriptEngineFactory().getScriptEngine("--language=es6");

            LOGGER.info("Loading handler script " + handlerScriptName);

            engine.setContext(ctx);
            engine.eval(r);

            handlerImpl = (Invocable) engine;
            return handlerImpl;
        }
        catch (ScriptException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    private VariableBinding[] getValue(String source, String target, int type, OID oid, Integer32 reqID, int repetitions) {
        if (LOGGER.isDebugEnabled()) LOGGER.debug("getValue(source=" + source + ", target=" + target + ", oid=" + oid + ")");

        try {
            // Check the watch service to see whether the script has changed (and reload)
            for (WatchKey key = watchService.poll(); key != null; key = watchService.poll()) {
                for (WatchEvent<?> event : key.pollEvents()) {
                    final var path = (Path) event.context();
                    if (event.kind() != StandardWatchEventKinds.OVERFLOW && path.endsWith(handlerScriptName)) {
                        handlerImpl = getHandlerScript();
                        break;
                    }
                }
                key.reset();
            }

            String method;
            switch (type)
            {
                case PDU.GET:
                    method = "get";
                    break;

                case PDU.GETNEXT:
                    method = "getnext";
                    break;

                case PDU.GETBULK:
                    method = "getbulk";
                    break;
                default:
                    return null;
            }

            var binding = handlerImpl.invokeFunction(method, source, target, oid.toDottedString(), reqID, repetitions);
            if (binding != null && LOGGER.isDebugEnabled()) LOGGER.debug("Invoked " + method + " with result class " + binding.getClass() + " and value: " + binding);

            if (binding instanceof VariableBinding) {
                var array = new VariableBinding[1];
                array[0] = (VariableBinding) binding;
                return array;
            }
            else {
                return (VariableBinding[]) binding;
            }
        }
        catch (NoSuchMethodException | ScriptException  e) {
            LOGGER.error("Error executing handler script", e);
            return null;
        }
    }

    @Override
    public void processPdu(CommandResponderEvent event)
    {
        try
        {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("  Peer address: " + event.getPeerAddress() + ", target address: " + ((NettyUdpTransportMapping) event.getTransportMapping()).getLocalIp());
            }

            var reqPdu = event.getPDU();
            var reqID = reqPdu.getRequestID();
            var repetitions = (reqPdu instanceof PDUv1) ? 0 : reqPdu.getMaxRepetitions();
            handleGet(event, reqPdu, reqID, repetitions);
        }
        catch (Throwable e)
        {
            LOGGER.error("Error handling request", e);
        }
    }

    private void handleGet(CommandResponderEvent event, PDU reqPdu, Integer32 reqID, int repetitions)
    {
        PDU pdu = (PDU) event.getPDU().clone();
        pdu.setType(PDU.RESPONSE);

        List<VariableBinding> newVariables = new ArrayList<>();

        String source = ((IpAddress) event.getPeerAddress()).getInetAddress().getHostAddress();
        String target = ((NettyUdpTransportMapping) event.getTransportMapping()).getLocalIp();
        for (VariableBinding reqVar : reqPdu.getVariableBindings())
        {
            var oid = reqVar.getOid();

            VariableBinding[] bindings = getValue(source, target, reqPdu.getType(), oid, reqID, repetitions);
            if (bindings == null)
            {
                pdu.setErrorStatus(SnmpConstants.SNMP_ERROR_NO_SUCH_NAME);
                if (event.getMessageProcessingModel() == MessageProcessingModel.MPv1)
                {
                    pdu.setErrorIndex(PDU.noSuchName);
                }
                else
                {
                    pdu.setErrorIndex(0);
                    reqVar.setVariable(Null.noSuchObject);
                }
                newVariables.add(reqVar);
            }
            else
            {
                Collections.addAll(newVariables, bindings);
            }
        }

        pdu.setVariableBindings(newVariables);

        try
        {
            snmp.getMessageDispatcher().returnResponsePdu(
                    event.getMessageProcessingModel(),
                    event.getSecurityModel(),
                    event.getSecurityName(),
                    event.getSecurityLevel(),
                    pdu,
                    event.getMaxSizeResponsePDU(),
                    event.getStateReference(),
                    new StatusInformation());
        }
        catch (MessageException e)
        {
            e.printStackTrace();
        }
    }

    private List<String> getBindAddresses() throws SocketException
    {
        var addresses = new ArrayList<String>();

        var ifaces = NetworkInterface.getNetworkInterfaces();
        while (ifaces.hasMoreElements())
        {
            var inetAddresses = ifaces.nextElement().getInetAddresses();
            while (inetAddresses.hasMoreElements())
            {
                String addr = inetAddresses.nextElement().getHostAddress();
                addresses.add(addr);
                LOGGER.debug("Added listen address: " + addr);
            }
        }

        return addresses;
    }

    private static Pattern TABLE_REGEX = Pattern.compile("table ([.\\d]+)\\.([.c]+)\\.([.r]+)");

    private class Table {
        private class TableRow {
            private ArrayList<VariableBinding> columns = new ArrayList<>();
        }

        private ArrayList<TableRow> tablesRows = new ArrayList<>();
    }

    private void loadMibs() throws IOException {
        class TableInfo {
            private String prefix;
            private String column;
            private String row;
            private Pattern tableRegex;
        }

        final var tableInfo = new TableInfo();
        final var tableRef = new AtomicReference<Table>();
        Files.list(Paths.get("."))
            .filter((path) -> path.endsWith(".snmp"))
            .forEach((path) -> {
                try {
                    var ipAddress = path.toFile().getName();
                    Files.lines(path, StandardCharsets.UTF_8)
                        .filter((line) -> !line.startsWith("#"))
                        .forEach((line) -> {
                            if (line.startsWith("table ")) {
                                var matchResult = TABLE_REGEX.matcher(line).toMatchResult();
                                if (matchResult.groupCount() == 0) return;
                                tableInfo.prefix = matchResult.group(1);
                                var colCardinality = countChars(matchResult.group(2), 'c');
                                var rowCardinality = countChars(matchResult.group(3), 'r');
                                var pattern = String.format("((?:\\.[.\\d]){%d})((?:\\.[.\\d]){%d}) =", colCardinality, rowCardinality);
                                tableInfo.tableRegex = Pattern.compile(pattern);
                                tableRef.set(new Table());
                                return;
                            }

                            if (tableInfo.tableRegex != null) {
                                var matcher = tableInfo.tableRegex.matcher(line);
                                if (matcher.find()) {
                                    var colIndex = matcher.group(2);
                                    var rowIndex = matcher.group(3);
                                    return;
                                }
                                else {
                                    tableInfo.tableRegex = null;
                                }
                            }

                            // non-table OID
                            tableInfo.prefix = null;
                        });
                    loadedMibs.put(ipAddress, null);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            });
    }

    private int countChars(final String str, final char c) {
        return (int) str.chars().filter(ch -> ch == c).count();
    }

    private void startServer() throws IOException
    {
        LOGGER.info("Starting SNMP server");

        loadMibs();

        var addresses = getBindAddresses();
        if (addresses.isEmpty())
        {
            LOGGER.warn("No addresses to bind to");
            return;
        }

        handlerImpl = getHandlerScript();

        watchService = FileSystems.getDefault().newWatchService();
        final Path path = Paths.get(handlerScriptName).getParent();
        path.register(watchService, StandardWatchEventKinds.ENTRY_MODIFY);

        NettyUdpTransportMapping transport = new NettyUdpTransportMapping(addresses, port);

        snmp = new Snmp(transport);
        snmp.addCommandResponder(this);
        USM usm = new USM(SecurityProtocols.getInstance(), new OctetString(MPv3.createLocalEngineID()), 0);
        SecurityModels.getInstance().addSecurityModel(usm);
        snmp.listen();

        LOGGER.info("Listening for SNMP requests");

        Semaphore semaphore = new Semaphore(0);
        semaphore.acquireUninterruptibly();
    }
}
