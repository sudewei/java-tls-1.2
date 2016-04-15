package jiayu.tls;

import java.io.IOException;
import java.net.Socket;

public interface RecordLayer {
    int MAX_RECORD_LENGTH = 16384;

    static RecordLayer getInstance(Socket socket) throws IOException {
        return new DefaultRecordLayerImpl(socket);
    }

    GenericProtocolMessage getNextIncomingMessage() throws IOException, FatalAlertException;

    void putNextOutgoingMessage(ProtocolMessage protocolMessage) throws IOException;

    void setEncryptionOn(boolean encryptionOn);
}
