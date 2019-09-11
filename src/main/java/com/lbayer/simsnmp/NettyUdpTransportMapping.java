package com.lbayer.simsnmp;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.epoll.EpollChannelOption;
import io.netty.channel.epoll.EpollDatagramChannel;
import io.netty.channel.epoll.EpollEventLoopGroup;
import io.netty.channel.group.DefaultChannelGroup;
import io.netty.channel.socket.DatagramChannel;
import io.netty.channel.socket.DatagramPacket;
import io.netty.channel.unix.UnixChannelOption;
import io.netty.handler.codec.bytes.ByteArrayEncoder;
import io.netty.util.concurrent.DefaultThreadFactory;
import io.netty.util.concurrent.GlobalEventExecutor;
import org.apache.log4j.Logger;
import org.snmp4j.TransportStateReference;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.transport.UdpTransportMapping;

import java.net.InetSocketAddress;
import java.util.List;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * SNMP4J NIO transport mapping.
 */
public class NettyUdpTransportMapping extends UdpTransportMapping
{
    private static final Logger LOGGER = Logger.getLogger(NettyUdpTransportMapping.class);
    private final List<String> addresses;

    private ThreadPoolExecutor executor;

    private DefaultChannelGroup channelGroup;
    private EventLoopGroup eventLoop;

    private int port;

    private ThreadLocal<TransportStateReference> localTransport;

    /**
     * Create the mapping.
     */
    NettyUdpTransportMapping(List<String> addresses, int port) {
        super(null);
        this.addresses = addresses;
        this.localTransport = new ThreadLocal<>();
        this.port = port;
    }

    @Override
    public boolean isListening()
    {
        return channelGroup != null && !channelGroup.isEmpty();
    }

    @Override
    public void listen()
    {
        executor = new ThreadPoolExecutor(1, 1, 10, TimeUnit.SECONDS, new LinkedBlockingDeque<>());
        executor.allowCoreThreadTimeOut(true);
        executor.setThreadFactory(new ThreadFactory() {
            private AtomicInteger count = new AtomicInteger();

            @Override
            public Thread newThread(Runnable r) {
                var t = new Thread(r, "SNMP Worker " + count.getAndIncrement());
                t.setDaemon(true);
                t.setUncaughtExceptionHandler((t1, e) -> {
                    LOGGER.error("Uncaught exception", e);
                    Thread.getDefaultUncaughtExceptionHandler().uncaughtException(t1, e);
                });
                return t;
            }
        });

        channelGroup = new DefaultChannelGroup(GlobalEventExecutor.INSTANCE);

        eventLoop = new EpollEventLoopGroup(1, new DefaultThreadFactory("SNMP Event Thread", true));

        int receiveBufferSize = (1 << 16) - 1;
        for (var address : addresses) {
            var datagramChannel = new Bootstrap()
                .group(eventLoop)
                .channel(EpollDatagramChannel.class)
                .option(EpollChannelOption.IP_RECVORIGDSTADDR, true)
                .option(ChannelOption.SO_RCVBUF, receiveBufferSize)
                .option(UnixChannelOption.SO_REUSEPORT, true)
                .option(ChannelOption.MESSAGE_SIZE_ESTIMATOR, new DefaultMessageSizeEstimator(receiveBufferSize))
                .handler(new ChannelInitializer<DatagramChannel>() {
                    @Override
                    protected void initChannel(DatagramChannel c) {
                        c.pipeline().addLast(new SnmpDecoder(), new ByteArrayEncoder());
                    }

                    @Override
                    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
                        super.exceptionCaught(ctx, cause);
                        LOGGER.error("Error in SNMP listener", cause);
                    }
                })
                .bind(new InetSocketAddress(address, port))
                .syncUninterruptibly()
                .channel();

            channelGroup.add(datagramChannel);
        }
    }

    @Override
    public void close() {
        if (channelGroup != null)
        {
            try {
                channelGroup.close().sync();
                channelGroup = null;

                eventLoop.shutdownGracefully();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    @Override
    public void sendMessage(UdpAddress targetAddress, byte[] message, TransportStateReference transportStateReference) {
        var inetAddress = targetAddress.getInetAddress();
        var socketAddress = new InetSocketAddress(inetAddress, targetAddress.getPort());

        var tsr = localTransport.get();
        var channel = (Channel) tsr.getSessionID();
        channel.writeAndFlush(new DatagramPacket(Unpooled.wrappedBuffer(message), socketAddress));
    }

    String getLocalIp() {
        var tsr = localTransport.get();
        if (tsr == null)
        {
            return null;
        }

        return ((UdpAddress) tsr.getAddress()).getInetAddress().getHostAddress();
    }

    /**
     * SNMP response handler
     */
    private class SnmpDecoder extends SimpleChannelInboundHandler<DatagramPacket> {
        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            LOGGER.warn("Exception caught processing SNMP response", cause);
        }

        @Override
        protected void channelRead0(final ChannelHandlerContext ctx, final DatagramPacket packet) {
            packet.retain();

            executor.execute(() -> {
                try
                {
                    var channel = ctx.channel();
                    var remoteAddress = packet.sender();
                    var localAddress = packet.recipient();
                    var localUdpAddress = new UdpAddress(localAddress.getAddress(), localAddress.getPort());

                    var tsr = new TransportStateReference(NettyUdpTransportMapping.this, localUdpAddress, null, SecurityLevel.undefined, SecurityLevel.undefined, false, channel);
                    localTransport.set(tsr);

                    fireProcessMessage(new UdpAddress(remoteAddress.getAddress(), remoteAddress.getPort()), packet.content().nioBuffer(), tsr);
                }
                finally
                {
                    packet.release();
                }
            });
        }
    }
}
