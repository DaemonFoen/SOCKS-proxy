package org.nsu.proxy;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.nsu.cli.CLI;
import org.nsu.dns.DNSResolver;
import org.xbill.DNS.ResolverConfig;

@Log4j2
@RequiredArgsConstructor
public class SocksProxyServer {
    private DNSResolver dnsResolver;
    private final int DNS_PORT = 53;
    public Selector selector;

    private final int port;

    public static void main(String[] args) {
        SocksProxyServer server = new SocksProxyServer(CLI.parse(args));
        server.proxy();
    }

    public void proxy() {
        try {
            selector = Selector.open();
            DatagramChannel dnsChannel = DatagramChannel.open();
            dnsChannel.configureBlocking(false);
            SocketAddress dnsServerAddress = new InetSocketAddress(
                    ResolverConfig.getCurrentConfig().servers().get(0).getAddress(),
                    DNS_PORT);
            dnsChannel.connect(dnsServerAddress);
            dnsChannel.register(selector, SelectionKey.OP_READ);

            dnsResolver = new DNSResolver(dnsChannel);

            ServerSocketChannel serverSocketChannel = ServerSocketChannel.open();
            serverSocketChannel.socket().bind(new InetSocketAddress(port));
            serverSocketChannel.configureBlocking(false);
            serverSocketChannel.register(selector, SelectionKey.OP_ACCEPT);

            while (selector.select() > -1) {
                SelectionKey key = null;
                try {
                    Iterator<SelectionKey> keyIterator = selector.selectedKeys().iterator();
                    while (keyIterator.hasNext()) {
                        key = keyIterator.next();
                        keyIterator.remove();
                        if (key.isAcceptable()) {
                            acceptConnection(key);
                        } else if (key.isConnectable()) {
                            finishConnect(key);
                        } else if (key.isReadable()) {
                            if (key.channel() instanceof DatagramChannel) {
                                dnsResolver.resolveAnsHandler(key);
                            } else {
                                read(key);
                            }
                        } else if (key.isWritable()) {
                            write(key);
                        }
                    }
                } catch (IOException e) {
                    log.debug(e.getMessage());
                    closeConnection(key);
                }
            }
        } catch (IOException e) {
            log.debug(e.getMessage());
        }
    }

    private void acceptConnection(SelectionKey key) throws IOException {
        SocketChannel clientSocketChannel = ((ServerSocketChannel) key.channel()).accept();
        clientSocketChannel.configureBlocking(false);
        clientSocketChannel.register(key.selector(), SelectionKey.OP_READ);
    }


    private void finishConnect(SelectionKey serverKey) throws IOException {
        SocketChannel channel;
        try {
            channel = ((SocketChannel) serverKey.channel());
            Attachment attachment = ((Attachment) serverKey.attachment());
            channel.finishConnect();
            log.debug("finish connect to " + channel.getRemoteAddress());
            attachment.getIn().put(attachment.getReply().put(1, (byte) 0)).flip();
            attachment.setOut(((Attachment) attachment.getDestinationKey().attachment()).getIn());
            ((Attachment) attachment.getDestinationKey().attachment()).setOut(attachment.getIn());
            attachment.getDestinationKey().interestOps(SelectionKey.OP_WRITE | SelectionKey.OP_READ);
            serverKey.interestOps(0);
        } catch (IOException e) {
            log.debug(e);
            closeConnection(((Attachment) serverKey.attachment()).getDestinationKey());
        }
    }


    private void read(SelectionKey key) throws IOException {
        SocketChannel channel = ((SocketChannel) key.channel());
        Attachment attachment = ((Attachment) key.attachment());
        if (attachment == null) {
            key.attach(attachment = new Attachment());
            attachment.setKey(key);
        }
        int size = channel.read(attachment.getIn());
        if (size == -1) {
            closeConnection(key);
        } else if (attachment.getDestinationKey() == null) {
            readHeader(key, size);
        } else {
            attachment.getDestinationKey()
                    .interestOps(attachment.getDestinationKey().interestOps() | SelectionKey.OP_WRITE);
            key.interestOps(key.interestOps() ^ SelectionKey.OP_READ);
            attachment.getIn().flip();
        }

    }

    private static void write(SelectionKey key) throws IOException {
        SocketChannel channel = ((SocketChannel) key.channel());
        Attachment attachment = ((Attachment) key.attachment());
        if (channel.write(attachment.getOut()) == -1) {
            closeConnection(key);
        } else if (attachment.getOut().remaining() == 0) {
            if (attachment.getDestinationKey() == null) {
                closeConnection(key);
            } else {
                attachment.getOut().clear();
                attachment.getDestinationKey()
                        .interestOps(attachment.getDestinationKey().interestOps() | SelectionKey.OP_READ);
                key.interestOps(key.interestOps() ^ SelectionKey.OP_WRITE);
            }
        }
    }

    private void readHeader(SelectionKey clientKey, int size) throws IllegalStateException, IOException {
        Attachment clientAttachment = (Attachment) clientKey.attachment();
        byte[] header = clientAttachment.getIn().array();
        byte[] reply = new byte[size];
        System.arraycopy(header, 0, reply, 0, size);
        clientAttachment.setReply(ByteBuffer.wrap(reply));
        if (header[0] != 0x05 && header[1] != 1) {
            log.debug("Bad Request");
            closeConnection(clientKey);
        }
        switch (clientAttachment.getState()) {
            case AUTH -> {
                SocketChannel channel = ((SocketChannel) clientKey.channel());
                channel.write((ByteBuffer.wrap(new byte[]{5, 0})));
                clientAttachment.setState(State.CONNECTING);
                clientAttachment.getIn().clear();
            }
            case CONNECTING -> {
                byte[] addr = null;
                switch (header[3]) {
                    case 0x01 -> {
                        addr = new byte[]{header[4], header[5], header[6], header[7]};
                        int port = (((0xFF & header[8]) << 8) + (0xFF & header[9]));
                        clientAttachment.setPort(port);
                    }
                    case 0x03 -> {
                        int port = (((0xFF & header[size - 2]) << 8) + (0xFF & header[size - 1]));
                        clientAttachment.setPort(port);
                        addr = new byte[header[4]];
                        System.arraycopy(header, 5, addr, 0, header[4]);
                        dnsResolver.resolve(new String(addr, StandardCharsets.UTF_8), clientKey);
                        return;
                    }
                }
                assert addr != null;
                startConnect(addr, clientAttachment);
            }
            default -> throw new IllegalStateException("Unrecognized state");
        }
    }

    public static void startConnect(byte[] address, Attachment context) throws IOException {
        SocketChannel destinationChannel = SocketChannel.open();
        destinationChannel.configureBlocking(false);
        destinationChannel.connect(new InetSocketAddress(InetAddress.getByAddress(address), context.getPort()));
        log.debug("start connecting to " + destinationChannel.getRemoteAddress());
        SelectionKey destinationKey = destinationChannel.register(context.getKey().selector(), SelectionKey.OP_CONNECT);
        context.getKey().interestOps(0);
        ((Attachment) context.getKey().attachment()).setDestinationKey(destinationKey);
        Attachment destinationAttachment = new Attachment();
        destinationAttachment.setKey(destinationKey);
        destinationAttachment.setDestinationKey(context.getKey());
        destinationAttachment.setPort(context.getPort());
        destinationKey.attach(destinationAttachment);
        destinationAttachment.setReply(context.getReply());
        ((Attachment) context.getKey().attachment()).getIn().clear();
    }

    private static void closeConnection(SelectionKey key) throws IOException {
        key.cancel();
        key.channel().close();
        log.debug("close connection");
        SelectionKey destinationKey = ((Attachment) key.attachment()).getDestinationKey();
        if (destinationKey != null) {
            ((Attachment) destinationKey.attachment()).setDestinationKey(null);
            if ((destinationKey.interestOps() & SelectionKey.OP_WRITE) == 0) {
                ((Attachment) destinationKey.attachment()).getOut().flip();
            }
            destinationKey.interestOps(SelectionKey.OP_WRITE);
        }
    }

}
