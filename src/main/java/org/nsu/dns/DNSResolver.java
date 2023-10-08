package org.nsu.dns;


import java.io.IOException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.nsu.proxy.Attachment;
import org.nsu.proxy.SocksProxyServer;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

@Log4j2
@RequiredArgsConstructor
public class DNSResolver {

    public final Map<Integer, Attachment> clientContextMap = new HashMap<>();
    private final int BUFFER_SIZE = 1024;

    private final DatagramChannel dnsChannel;


    public void resolve(String domainName, SelectionKey clientKey) throws IOException {
        clientKey.interestOps(0);
        byte[] queryData = createDnsQuery(domainName,(Attachment) clientKey.attachment());
        dnsChannel.write(ByteBuffer.wrap(queryData));
    }

    public void resolveAnsHandler(SelectionKey key) {
        try {
            DatagramChannel channel = (DatagramChannel) key.channel();
            ByteBuffer responseBuffer = ByteBuffer.allocate(BUFFER_SIZE);
            channel.read(responseBuffer);
            responseBuffer.flip();

            Message response = new Message(responseBuffer);
            List<Record> records = response.getSection(Section.ANSWER);
            Optional<ARecord> record = records.stream().filter(it -> it instanceof ARecord).limit(1)
                    .map(it -> (ARecord) it).findAny();
            byte[] address = record.orElseThrow(UnknownHostException::new).getAddress().getAddress();
            SocksProxyServer.startConnect(address, clientContextMap.remove(response.getHeader().getID()));
        } catch (IOException e){
            log.error(e);
        }
    }


    private byte[] createDnsQuery(String domainName, Attachment attachment) throws TextParseException {
        Message query = new Message();
        query.getHeader().setFlag(Flags.RD);
        query.addRecord(Record.newRecord(Name.fromString(new Name(domainName).isAbsolute()?domainName: domainName+"."), Type.A, DClass.IN), Section.QUESTION);
        clientContextMap.put(query.getHeader().getID(),attachment);
        return query.toWire();
    }
}