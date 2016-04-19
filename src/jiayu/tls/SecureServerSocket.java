package jiayu.tls;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

@SuppressWarnings("Duplicates")
public class SecureServerSocket {
    private byte[] serverCert;
    private PrivateKey serverKey;

    private ServerSocket serverSocket;

    public SecureServerSocket() {

    }

    public void setServerKey(Path keyFile) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        if (!Files.exists(keyFile)) throw new FileNotFoundException();
        if (!Files.isRegularFile(keyFile)) throw new IllegalArgumentException();

        byte[] keyBytes = Files.readAllBytes(keyFile);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        serverKey = KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    }

    public void setServerCert(Path cert) throws IOException {
        if (!Files.exists(cert)) throw new FileNotFoundException();

        serverCert = Files.readAllBytes(cert);
    }

    public void bind(int port) throws IOException {
        if (serverCert == null || serverKey == null)
            throw new IllegalStateException("not ready to accept connections");
        this.serverSocket = new ServerSocket(port);
    }

    public SecureSocket acceptSecured() throws IOException {
        if (serverSocket == null || serverCert == null || serverKey == null)
            throw new IllegalStateException("not ready to accept connections");

        Socket socket = serverSocket.accept();

        if (serverCert == null) throw new IllegalStateException();

        SecurityParameters currSecParams = new SecurityParameters(ConnectionEnd.CLIENT);
        ConnectionState currReadState = new ConnectionState();
        ConnectionState currWriteState = new ConnectionState();

        try {
            currReadState.init(currSecParams);
            currWriteState.init(currSecParams);
            System.out.println("Initialising current read and write states...");
            System.out.println("Current cipher suite: " + currSecParams.getCipherSuite().name());
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }

        RecordLayer recordLayer = RecordLayer.getInstance(socket, currReadState, currWriteState);

        SecurityParameters securityParameters = new SecurityParameters(ConnectionEnd.SERVER);
        ConnectionState pendingReadState = new ConnectionState();
        ConnectionState pendingWriteState = new ConnectionState();

        // receive client hello
        System.out.println("Waiting for ClientHello... ");
        ClientHello clientHello;
        try {
            clientHello = (ClientHello) recordLayer.getNextIncomingMessage()
                    .asHandshakeMessage(HandshakeType.CLIENT_HELLO);
//            System.out.println(clientHello);

            securityParameters.setClientRandom(clientHello.getRandom().toBytes());

            // choose cipher suite
            System.out.println("Client offered cipher suites: " + Arrays.toString(clientHello.getCipherSuites()));
            System.out.println("Choosing cipher suite... ");
            System.out.flush();
            CipherSuite selectedCipherSuite = clientHello.getCipherSuites()[0];
            System.out.println("Selected cipher suite: " + selectedCipherSuite.name());

            securityParameters.setCipherSuite(selectedCipherSuite);

            // send server hello
            System.out.println("Sending ServerHello... ");
            ServerHello serverHello = new ServerHello(selectedCipherSuite);
            recordLayer.putNextOutgoingMessage(serverHello);

            securityParameters.setServerRandom(serverHello.getRandom().toBytes());

            // send server serverCert
            System.out.println("Sending server Certificate... ");
            Certificate certificate = new Certificate(new ASN1Cert(this.serverCert));
            recordLayer.putNextOutgoingMessage(certificate);

            // send server hello done
            System.out.println("Sending ServerHelloDone... ");
            ServerHelloDone serverHelloDone = new ServerHelloDone();
            recordLayer.putNextOutgoingMessage(serverHelloDone);

            // receive ClientKeyExchange
            System.out.println("Waiting for ClientKeyExchange... ");
            ClientKeyExchange clientKeyExchange = (ClientKeyExchange) recordLayer.getNextIncomingMessage().asHandshakeMessage(HandshakeType.CLIENT_KEY_EXCHANGE);
            System.out.println("Reading premaster secret...");

            // read premaster secret
            PremasterSecret premasterSecret = PremasterSecret.fromBytes(clientKeyExchange.getEncryptedPremasterSecret());
            try {
                premasterSecret.decrypt(serverKey, clientHello.getClientVersion());
            } catch (BadPaddingException | InvalidKeyException | IllegalBlockSizeException e) {
                e.printStackTrace();
                throw new FatalAlertException(AlertDescription.DECRYPT_ERROR);
            } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
                throw new FatalAlertException(AlertDescription.INTERNAL_ERROR);
            }

            System.out.println("Decrypted premaster secret: " + DatatypeConverter.printBase64Binary(premasterSecret.getBytes()));

            // generate master secret
            MasterSecret masterSecret;
            System.out.println("Generating master secret...");
            //noinspection Duplicates
            try {
                masterSecret = MasterSecret.generateMasterSecret(premasterSecret, clientHello, serverHello);
                System.out.println("Master secret: " + DatatypeConverter.printBase64Binary(masterSecret.getBytes()));
            } catch (InvalidKeyException | NoSuchAlgorithmException e) {
                throw new FatalAlertException(AlertDescription.INTERNAL_ERROR);
            }

            securityParameters.setMasterSecret(masterSecret.getBytes());

            // now that all the security parameters have been established
            // initialise the next read and write states
            //noinspection Duplicates
            try {
                System.out.println("Initialising pending read and write states...");
                pendingWriteState.init(securityParameters);
                pendingReadState.init(securityParameters);
                System.out.println("Pending cipher suite: " + securityParameters.getCipherSuite().name());
            } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                e.printStackTrace();
                throw new FatalAlertException(AlertDescription.INTERNAL_ERROR);
            }

            // receive client ChangeCipherSpec
            /*
                Reception
                of this message causes the receiver to instruct the record layer to
                mmediately copy the read pending state into the read current state.
             */
            System.out.println("Waiting for client ChangeCipherSpec... ");
            recordLayer.getNextIncomingMessage().asChangeCipherSpecMessage();
            System.out.println("Made pending read state current.");

            // make pending read state current
            recordLayer.updateReadState(pendingReadState);
            currReadState = pendingReadState;

            // ideally, the record layer should have decrypted the message for us
            System.out.println("Waiting for client Finished....");
            Finished clientFinished = (Finished) recordLayer.getNextIncomingMessage().asHandshakeMessage(HandshakeType.FINISHED);

            // verify client Finished message
            System.out.println("Verifying client Finished... ");
            Finished clientFinishedVerify = Finished.createClientFinishedMessage(masterSecret,
                    clientHello, serverHello, certificate, serverHelloDone, clientKeyExchange);
            if (!Arrays.equals(clientFinished.getContent(), clientFinishedVerify.getContent()))
                throw new FatalAlertException(AlertDescription.DECRYPT_ERROR);

            // send server ChangeCipherSpec message
            /*
                Immediately after sending this message, the sender MUST instruct the
                record layer to make the write pending state the write active state.
             */
            System.out.println("Sending server ChangeCipherSpec... ");
            ChangeCipherSpecMessage changeCipherSpecMessage = new ChangeCipherSpecMessage();
            recordLayer.putNextOutgoingMessage(changeCipherSpecMessage);
            System.out.println("Made write pending state current.");

            // make the pending write state the current write state
            recordLayer.updateWriteState(pendingWriteState);
            currWriteState = pendingWriteState;

            // send server Finished message
            System.out.println("Sending server Finished...");
            Finished serverFinished = Finished.createServerFinishedMessage(masterSecret,
                    clientHello, serverHello, certificate, serverHelloDone, clientKeyExchange, clientFinished);
            recordLayer.putNextOutgoingMessage(serverFinished);

            System.out.println("Handshake complete.");

            return new SecureSocket(recordLayer);
        } catch (FatalAlertException e) {
            e.printStackTrace();
            throw new IOException();
        }
    }


    public void close() throws IOException {
        serverSocket.close();
    }
}
