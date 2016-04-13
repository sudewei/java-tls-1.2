package jiayu.tls;

import java.io.ByteArrayInputStream;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;

public interface Writable {
    byte[] toBytes();

    default ReadableByteChannel toReadableByteChannel() {
        return Channels.newChannel(new ByteArrayInputStream(toBytes()));
    }
}
