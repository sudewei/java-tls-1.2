package jiayu.tls;

import java.io.IOException;
import java.net.Socket;

public interface RecordLayer {
    int MAX_RECORD_LENGTH = 16384;

    static RecordLayer getInstance(Socket socket, ConnectionState state) throws IOException {
        return new DefaultRecordLayerImpl(socket, state);
    }

    GenericProtocolMessage getNextIncomingMessage() throws IOException, FatalAlertException;

    void updateConnectionState(ConnectionState newState);

    void putNextOutgoingMessage(ProtocolMessage protocolMessage) throws IOException;
}
