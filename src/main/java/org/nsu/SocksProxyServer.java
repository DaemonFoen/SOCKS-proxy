package org.nsu;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import lombok.extern.log4j.Log4j2;
import org.xbill.DNS.ResolverConfig;

@Log4j2
public class SocksProxyServer {

    private DNSResolver dnsResolver;
    static final int BUFFER_SIZE = 8192;
    public static Selector selector;
//    static final byte[] OK = new byte[]{0x05, 0x00, 0x00, 0x01, -110, 75, 117, -116, 1, -69};

    public static void main(String[] args) {
        SocksProxyServer server = new SocksProxyServer();
        server.proxy(50000);
    }

    public void proxy(int proxyPort) {
        try {
            selector = Selector.open();
            DatagramChannel dnsChannel = DatagramChannel.open();
            dnsChannel.configureBlocking(false);
            int DNS_PORT = 53;
            SocketAddress dnsServerAddress = new InetSocketAddress(
                    ResolverConfig.getCurrentConfig().servers().get(0).getAddress(),
                    DNS_PORT);
            dnsChannel.connect(dnsServerAddress);
            dnsChannel.register(selector, SelectionKey.OP_READ);

            dnsResolver = new DNSResolver(dnsChannel);

            ServerSocketChannel serverSocketChannel = ServerSocketChannel.open();
            serverSocketChannel.socket().bind(new InetSocketAddress(proxyPort));
            serverSocketChannel.configureBlocking(false);
            serverSocketChannel.register(selector, SelectionKey.OP_ACCEPT);

            while (selector.select() > -1) {
                try {

                Iterator<SelectionKey> keyIterator = selector.selectedKeys().iterator();
                while (keyIterator.hasNext()) {
                    SelectionKey key = keyIterator.next();
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
                    log.error(e.getMessage());
                }
            }
        } catch (IOException e) {
            log.error(e.getMessage());
        }
    }

    private void acceptConnection(SelectionKey key) throws IOException {
        SocketChannel clientSocketChannel = ((ServerSocketChannel) key.channel()).accept();
        clientSocketChannel.configureBlocking(false);
        clientSocketChannel.register(key.selector(), SelectionKey.OP_READ);
        System.out.println("accept connection");
    }


    private void finishConnect(SelectionKey serverKey) throws IOException {
        //Destination server side
        System.out.println("connect");
        SocketChannel channel = ((SocketChannel) serverKey.channel());
        Attachment attachment = ((Attachment) serverKey.attachment());
        channel.finishConnect();
        attachment.setIn(ByteBuffer.allocate(BUFFER_SIZE));
        attachment.getIn().put(attachment.getReply().put(1, (byte) 0)).flip();
        attachment.setOut(((Attachment) attachment.getDestinationKey().attachment()).getIn());
        ((Attachment) attachment.getDestinationKey().attachment()).setOut(attachment.getIn());
        attachment.getDestinationKey().interestOps(SelectionKey.OP_WRITE | SelectionKey.OP_READ);
        serverKey.interestOps(0);
    }


    private void read(SelectionKey key) throws IOException {
//        System.out.println("read");
        SocketChannel channel = ((SocketChannel) key.channel());
        Attachment attachment = ((Attachment) key.attachment());
        if (attachment == null) {
            key.attach(attachment = new Attachment());
            attachment.setIn(ByteBuffer.allocate(BUFFER_SIZE));
            attachment.setState(State.AUTH);
            attachment.setKey(key);
        }
        int size = channel.read(attachment.getIn());
        if (size < 1) {
            // -1 - разрыв 0 - нету места в буфере, такое может быть только если
            // заголовок превысил размер буфера
            closeConnection(key);
        } else if (attachment.getDestinationKey() == null) {
            //Нет соединения, значит читаем заголовок
            readHeader(key,size);
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
        System.arraycopy(header,0,reply,0,size);
        clientAttachment.setReply(ByteBuffer.wrap(reply));
        if (header[0] != 0x05 && header[1] != 1) {
            throw new IllegalStateException("Bad Request");
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
                        int port = (((0xFF & header[3]) << 8) + (0xFF & header[4]));
                        clientAttachment.setPort(port);
                        addr = new byte[header[4]];
                        System.arraycopy(header, 5, addr, 0, header[4]);
                        dnsResolver.resolve(new String(addr, StandardCharsets.UTF_8), clientKey);
                        System.out.println("ip - Domain " + port);
                        return;
                    }
                }
                assert addr != null;
//                System.out.println("ip" + InetAddress.getByAddress(addr) + "  " + port);
                startConnect(addr, clientAttachment);
            }
            case PROXY -> throw new IllegalStateException("Proxy state");
        }
    }

    public static void startConnect(byte[] address, Attachment context) throws IOException {
        SocketChannel destinationChannel = SocketChannel.open();
        destinationChannel.configureBlocking(false);
        System.out.println(InetAddress.getByAddress(address).getHostAddress() + context.getPort());
        destinationChannel.connect(new InetSocketAddress(InetAddress.getByAddress(address), context.getPort()));
        SelectionKey destinationKey = destinationChannel.register(context.getKey().selector(), SelectionKey.OP_CONNECT);
        context.getKey().interestOps(0);
        context.setState(State.PROXY);
        ((Attachment) context.getKey().attachment()).setDestinationKey(destinationKey);
        Attachment destinationAttachment = new Attachment();
        destinationAttachment.setState(State.PROXY);
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
