package jiayu.tls;

import java.io.IOException;
import java.net.Socket;

public interface RecordLayer {
    int MAX_RECORD_LENGTH = 16384;

    static RecordLayer getInstance(Socket socket, ConnectionState readState, ConnectionState writeState) throws IOException {
        return new DefaultRecordLayerImpl(socket, writeState, readState);
    }

    GenericProtocolMessage getNextIncomingMessage() throws IOException, FatalAlertException;

    void putNextOutgoingMessage(ProtocolMessage protocolMessage) throws IOException;

    ConnectionState getWriteState();

    void updateWriteState(ConnectionState newState);

    ConnectionState getReadState();

    void updateReadState(ConnectionState newState);
}
