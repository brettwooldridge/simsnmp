package com.lbayer.simsnmp;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.DatagramPacket;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.handler.codec.bytes.ByteArrayEncoder;
import io.netty.util.concurrent.DefaultThreadFactory;
import org.apache.log4j.Logger;
import org.snmp4j.TransportStateReference;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.transport.UdpTransportMapping;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
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

    private List<Channel> channels;

    private ThreadPoolExecutor executor;

    private NioEventLoopGroup eventLoop;
    private List<String> addresses;
    private int port;

    private ThreadLocal<TransportStateReference> localTransport;

    /**
     * Create the mapping.
     */
    NettyUdpTransportMapping(List<String> addresses, int port) {
        super(null);
        localTransport = new ThreadLocal<>();
        this.addresses = addresses;
        this.port = port;
    }

    @Override
    public boolean isListening()
    {
        return channels != null && !channels.isEmpty();
    }

    @Override
    public void listen() {
        executor = new ThreadPoolExecutor(2, 2, 10, TimeUnit.SECONDS, new LinkedBlockingDeque<>());
        executor.allowCoreThreadTimeOut(true);
        executor.setThreadFactory(new ThreadFactory()
        {
            private AtomicInteger count = new AtomicInteger();

            @Override
            public Thread newThread(Runnable r)
            {
                Thread t = new Thread(r, "SNMP Worker " + count.getAndIncrement());
                t.setDaemon(true);
                t.setUncaughtExceptionHandler((t1, e) -> {
                    LOGGER.error("Uncaught exception", e);
                    Thread.getDefaultUncaughtExceptionHandler().uncaughtException(t1, e);
                });
                return t;
            }
        });

        eventLoop = new NioEventLoopGroup(1, new DefaultThreadFactory("SNMP Event Thread", true));

        channels = new ArrayList<>();
        for (String address : addresses)
        {
            int receiveBufferSize = (1 << 16) - 1;
            channels.add(
                new Bootstrap()
                    .group(eventLoop)
                    .channel(NioDatagramChannel.class)
                    .option(ChannelOption.SO_RCVBUF, receiveBufferSize)
                    .option(ChannelOption.MESSAGE_SIZE_ESTIMATOR, new DefaultMessageSizeEstimator(receiveBufferSize))
                    .handler(new ChannelInitializer<Channel>()
                    {
                        @Override
                        protected void initChannel(Channel c) {
                            c.pipeline().addLast(new SnmpDecoder(), new ByteArrayEncoder());
                        }

                        @Override
                        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception
                        {
                            super.exceptionCaught(ctx, cause);
                            LOGGER.error("Error in SNMP listener", cause);
                        }
                    })
                    .bind(new InetSocketAddress(address, port))
                    .syncUninterruptibly()
                    .channel()
            );
        }
    }

    @Override
    public void close() {
        if (channels != null)
        {
            for (Channel channel : channels)
            {
                channel.close().syncUninterruptibly();
            }

            channels = null;

            eventLoop.shutdownGracefully();
        }
    }

    @Override
    public void sendMessage(UdpAddress targetAddress, byte[] message, TransportStateReference transportStateReference) {
        InetAddress inetAddress = targetAddress.getInetAddress();
        InetSocketAddress socketAddress = new InetSocketAddress(inetAddress, targetAddress.getPort());

        TransportStateReference t = localTransport.get();
        Channel channel = (Channel) t.getSessionID();
        channel.writeAndFlush(new DatagramPacket(Unpooled.wrappedBuffer(message), socketAddress));
    }

    String getLocalIp() {
        TransportStateReference t = localTransport.get();
        if (t == null)
        {
            return null;
        }

        return ((UdpAddress) t.getAddress()).getInetAddress().getHostAddress();
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
                    Channel channel = ctx.channel();
                    InetSocketAddress remoteAddress = packet.sender();
                    InetSocketAddress localAddress = (InetSocketAddress) channel.localAddress();
                    UdpAddress localUdpAddress = new UdpAddress(localAddress.getAddress(), localAddress.getPort());

                    TransportStateReference tsr = new TransportStateReference(NettyUdpTransportMapping.this, localUdpAddress, null, SecurityLevel.undefined, SecurityLevel.undefined, false, channel);
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
