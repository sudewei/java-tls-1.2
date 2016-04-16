package jiayu.tls;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static jiayu.tls.ContentType.*;

class DefaultRecordLayerImpl implements RecordLayer {
    private final Socket socket;

    private final DataOutputStream out;
    private final DataInputStream in;

    private ConnectionState readState;
    private ConnectionState writeState;

    private ContentType leftoversType;
    private ByteQueue inputQueue;

    DefaultRecordLayerImpl(Socket socket, ConnectionState readState, ConnectionState writeState) throws IOException {
        this.socket = socket;
        out = new DataOutputStream(socket.getOutputStream());
        in = new DataInputStream(socket.getInputStream());

        updateWriteState(writeState);
        updateReadState(readState);

        inputQueue = new ByteQueue();
    }

    @Override
    public GenericProtocolMessage getNextIncomingMessage() throws FatalAlertException {
        // invariant: contents of next record or leftoverbytes are a new message from the beginning
        ContentType nextMsgType;

        try {
            // if inputqueue is empty, fill it with content from the next incoming record
            if (inputQueue.isEmpty()) {
                TLSPlaintext nextIncRecord = getNextIncomingRecord();
                nextMsgType = nextIncRecord.getContentType();
                inputQueue.enqueue(nextIncRecord.getContent());
            } else {
                nextMsgType = leftoversType;
            }

            switch (nextMsgType) {
                case CHANGE_CIPHER_SPEC:
                    // change cipher specs are only sent one at a time
                    // so there should only be one inside a single record
                    // and a record cannot be empty

                    if (inputQueue.size() != ChangeCipherSpecMessage.BYTES)
                        throw new FatalAlertException(AlertDescription.DECODE_ERROR);

                    return new GenericProtocolMessage(CHANGE_CIPHER_SPEC, inputQueue.dequeue(ChangeCipherSpecMessage.BYTES));
                case ALERT:
                    // if there are not enough content for an alert,
                    // we get more content from the next incoming record
                    while (inputQueue.size() < AlertMessage.BYTES) updateInputQueue(ALERT);

                    byte[] incAlertContent = inputQueue.dequeue(AlertMessage.BYTES);
                    if (new AlertMessage(incAlertContent).getLevel() == AlertLevel.FATAL)
                        throw new RuntimeException("Received fatal alert, connection terminated");
                    if (!inputQueue.isEmpty()) leftoversType = ALERT;
                    return new GenericProtocolMessage(ALERT, incAlertContent);
                case HANDSHAKE:
                    // we need to read the header of the incoming message to find out how long it is
                    // but if the entire header has not been received yet,
                    // we get more content from the next incoming record
                    while (inputQueue.size() < HandshakeMessage.HEADER_LENGTH) updateInputQueue(HANDSHAKE);

                    byte[] length = inputQueue.peek(3, 1);  // handshake length field is 3 content long
                    int incHandshakeLength = UInt.btoi(length);

                    // if the entire of the incoming handshake is not in the input queue yet,
                    // we get more content from the next incoming record
                    while (inputQueue.size() < HandshakeMessage.HEADER_LENGTH + incHandshakeLength)
                        updateInputQueue(nextMsgType);

                    byte[] incHandshakeContent = inputQueue.dequeue(HandshakeMessage.HEADER_LENGTH + incHandshakeLength);
                    if (!inputQueue.isEmpty()) leftoversType = HANDSHAKE;
                    return new GenericProtocolMessage(HANDSHAKE, incHandshakeContent);
                case APPLICATION_DATA:
                    return new GenericProtocolMessage(APPLICATION_DATA, inputQueue.dequeue(inputQueue.size()));
                default:
                    throw new FatalAlertException(AlertDescription.DECODE_ERROR);
            }

        } catch (IOException e) {
            e.printStackTrace();
            throw new FatalAlertException(AlertDescription.DECODE_ERROR);
        }
    }

    /**
     * Reads the next incoming Record and adds its contents to the input queue
     *
     * @param nextMsgType The expected content type of the next record
     * @throws IOException         If an I/O error occurs
     * @throws FatalAlertException If the content type of the next record is not what was expected
     */
    private void updateInputQueue(ContentType nextMsgType) throws IOException, FatalAlertException {
        TLSPlaintext nextRecord = getNextIncomingRecord();
        if (nextRecord.getContentType() != nextMsgType)
            throw new FatalAlertException(AlertDescription.UNEXPECTED_MESSAGE);
        inputQueue.enqueue(nextRecord.getContent());
    }

    private TLSPlaintext getNextIncomingRecord() throws IOException, FatalAlertException {
        ByteBuffer recordHeader = ByteBuffer.allocate(5);
        // TODO: 15/04/2016 handle eofexception
        in.readFully(recordHeader.array());

        ContentType incRecordType = ContentType.valueOf(recordHeader.get());  // get next record type
        short incRecordProtocol = recordHeader.getShort();                    // get next record protocol
        int incRecordLength = recordHeader.getShort();                        // get next record length

        byte[] incRecordContent = new byte[incRecordLength];
        in.readFully(incRecordContent);

        if (readState.getEncryptionAlgorithm() == null) {
            return new TLSPlaintext(incRecordType, incRecordProtocol, incRecordContent);
        } else {
            TLSCiphertext nextIncRecord = new TLSCiphertext(incRecordType, incRecordProtocol, incRecordContent);
            try {
                byte[] incContent = GenericBlockCipherEncryptionProvider.decrypt(readState, nextIncRecord);
                return new TLSPlaintext(incRecordType, incRecordProtocol, incContent);
            } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
                e.printStackTrace();
                throw new FatalAlertException(AlertDescription.INTERNAL_ERROR);
            }
        }
    }

    @Override
    public void putNextOutgoingMessage(ProtocolMessage message) throws IOException {
        // no encryption
        if (writeState.getEncryptionAlgorithm() == null) {
            TLSPlaintext tlsPlaintext = new TLSPlaintext(message);
            out.write(tlsPlaintext.getBytes());
        } else {
            // else we need to encrypt the message before sending it
            try {
                GenericBlockCipher encryptedMessage = GenericBlockCipherEncryptionProvider.encrypt(writeState, message);
                TLSCiphertext tlsCiphertext = new TLSCiphertext(encryptedMessage);
                out.write(tlsCiphertext.getBytes());
            } catch (InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException e) {
                e.printStackTrace();
            }
        }
    }

    @Override
    public ConnectionState getWriteState() {
        return writeState;
    }

    @Override
    public void updateWriteState(ConnectionState newState) {
        writeState = newState;
    }

    @Override
    public ConnectionState getReadState() {
        return writeState;
    }

    @Override
    public void updateReadState(ConnectionState newState) {
        readState = newState;
    }

    @Override
    public void close() throws IOException {
        putNextOutgoingMessage(AlertMessage.fatal(AlertDescription.USER_CANCELLED));
        out.close();
    }
}
