package jiayu.tls;

import java.io.IOException;
import java.net.SocketException;
import java.nio.channels.SocketChannel;

public interface RecordLayer {
    int MAX_RECORD_LENGTH = 16384;

    static RecordLayer getInstance(SocketChannel sc) throws SocketException {
        return new DefaultRecordLayerImpl(sc);
    }

    GenericProtocolMessage getNextIncomingMessage() throws IOException, FatalAlertException;

    void putNextOutgoingMessage(ProtocolMessage protocolMessage) throws IOException;
}
