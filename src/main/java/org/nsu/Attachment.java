package org.nsu;

import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;

@Data
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
@NoArgsConstructor
public class Attachment {
    SelectionKey key;
    int port;
    State state;
    //Ответ клиенту
    ByteBuffer reply;
    ByteBuffer in;
    ByteBuffer out;
    SelectionKey destinationKey;
}

enum State{
    AUTH,
    CONNECTING,
    PROXY
}