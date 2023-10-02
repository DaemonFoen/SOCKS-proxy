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
    static final int BUFFER_SIZE = 8192;

    {
        this.setIn(ByteBuffer.allocate(BUFFER_SIZE));
        this.setState(State.AUTH);
    }

    SelectionKey key;
    int port;
    State state;
    ByteBuffer reply;
    ByteBuffer in;
    ByteBuffer out;
    SelectionKey destinationKey;
}

enum State{
    AUTH,
    CONNECTING,
}