package jiayu;

import jiayu.tls.*;
import jiayu.tls.Certificate;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

@SuppressWarnings("Duplicates")
public class Client {
    public static final short CLIENT_VERSION = 0x0303;

    // magic number for acknowledging successful upload
    private static final long UPLOAD_SUCCESS = 6584997751L;
    private static final CipherSuite[] SUPPORTED_CIPHER_SUITES = new CipherSuite[]{CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256};

    private X509Certificate caCert;

    private int sessionId;

    public void setCACertificate(Path caCert) throws IOException, CertificateException {
        if (!Files.exists(caCert)) throw new FileNotFoundException();
        if (!Files.isRegularFile(caCert)) throw new IllegalArgumentException();

        this.caCert = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(Files.newInputStream(caCert));
    }

    public RecordLayer connectSecured(String serverAddress, int port) throws IOException {
        Socket socket = new Socket(serverAddress, port);

        SecurityParameters currSecParams = new SecurityParameters(ConnectionEnd.CLIENT);
        ConnectionState currReadState = new ConnectionState();
        ConnectionState currWriteState = new ConnectionState();

        try {
            currReadState.init(currSecParams);
            currWriteState.init(currSecParams);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }

        RecordLayer recordLayer = RecordLayer.getInstance(socket, currReadState, currWriteState);

        SecurityParameters securityParameters = new SecurityParameters(ConnectionEnd.CLIENT);
        ConnectionState pendingReadState = new ConnectionState();
        ConnectionState pendingWriteState = new ConnectionState();

        // send client hello
        System.out.print("Sending client hello... ");
        System.out.flush();
        ClientHello clientHello = new ClientHello(SUPPORTED_CIPHER_SUITES);
        recordLayer.putNextOutgoingMessage(clientHello);
        System.out.println("Done.");

        securityParameters.setClientRandom(clientHello.getRandom().toBytes());

        // receive server hello
        System.out.print("Waiting for ServerHello... ");
        System.out.flush();
        try {
            ServerHello serverHello = (ServerHello) recordLayer.getNextIncomingMessage()
                    .asHandshakeMessage(HandshakeType.SERVER_HELLO);
            System.out.println("Received.");

            securityParameters.setCipherSuite(serverHello.getCipherSuite());
            securityParameters.setServerRandom(serverHello.getRandom().toBytes());

            // receive server certificate
            System.out.print("Waiting for Certificate... ");
            System.out.flush();
            Certificate certificate = (Certificate) recordLayer.getNextIncomingMessage()
                    .asHandshakeMessage(HandshakeType.CERTIFICATE);
            System.out.println("Received.");


            // wait for serverhellodone
            System.out.print("Waiting for ServerHelloDone... ");
            System.out.flush();
            ServerHelloDone serverHelloDone = (ServerHelloDone) recordLayer.getNextIncomingMessage()
                    .asHandshakeMessage(HandshakeType.SERVER_HELLO_DONE);
            System.out.println("Received.");

            // authenticate server certificate
            // FIXME: 15/04/2016 authenticates each cert individually instead of as a chain
            /*
                I need to check each certificate against the next cert in the certificate list
                if the certificate is the last ecrt in the certificate list
                we check it against the cacert instead

                the server cert is always the first certificate in the list
             */
            PublicKey serverPublicKey;
            System.out.println("Authenticating server certificates... ");
            CertificateList certChain = certificate.getCertificateList();
            X509Certificate serverCert = null;
            X509Certificate prev = null;
            X509Certificate current;
            try {
                for (ASN1Cert asn1Cert : certChain.getContents()) {
                    if (prev == null) {
                        serverCert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(asn1Cert.getContent()));
                        System.out.println("Server DN: " + serverCert.getSubjectX500Principal().getName());
                        serverCert.checkValidity();
                        prev = serverCert;
                    } else {
                        current = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(asn1Cert.getContent()));
                        System.out.println("Current DN: " + current.getSubjectX500Principal().getName());
                        current.checkValidity();
                        prev.verify(current.getPublicKey());
                    }
                }
                assert prev != null;
                prev.verify(caCert.getPublicKey());
                serverPublicKey = serverCert.getPublicKey();
                System.out.println("Authenticated.");

            } catch (CertificateExpiredException e) {
                throw new FatalAlertException(AlertDescription.CERTIFICATE_EXPIRED);
            } catch (CertificateException | SignatureException e) {
                throw new FatalAlertException(AlertDescription.BAD_CERTIFICATE);
            } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException e) {
                throw new FatalAlertException(AlertDescription.INTERNAL_ERROR);
            }

            // generate and send pre-master key
            CipherSuite selectedCipherSuite = serverHello.getCipherSuite();
            PremasterSecret premasterSecret;
            ClientKeyExchange clientKeyExchange;
            if (selectedCipherSuite.keyExchangeAlgorithm == KeyExchangeAlgorithm.RSA) {
                premasterSecret = PremasterSecret.newRSAPremasterSecret(CLIENT_VERSION);
                try {
                    clientKeyExchange = new ClientKeyExchange(premasterSecret.getEncryptedBytes(serverPublicKey));
                } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
                    throw new FatalAlertException(AlertDescription.INTERNAL_ERROR);
                }
                recordLayer.putNextOutgoingMessage(clientKeyExchange);
                System.out.println("Done.");
                System.out.println("Unencypted premaster secret: " + Arrays.toString(premasterSecret.getBytes()));
                System.out.println("Premaster secret length: " + premasterSecret.getBytes().length);
            } else {
                throw new FatalAlertException(AlertDescription.INTERNAL_ERROR);
            }

            // generate master secret
            MasterSecret masterSecret;
            //noinspection Duplicates
            try {
                masterSecret = MasterSecret.generateMasterSecret(premasterSecret, clientHello, serverHello);
                System.out.println("Master secret: " + Arrays.toString(masterSecret.getBytes()));
                System.out.println("Master secret length: " + masterSecret.getBytes().length);
            } catch (InvalidKeyException | NoSuchAlgorithmException e) {
                throw new FatalAlertException(AlertDescription.INTERNAL_ERROR);
            }

            securityParameters.setMasterSecret(masterSecret.getBytes());

            // now that all the security parameters have been established
            // initialise the next read and write states
            try {
                pendingWriteState.init(securityParameters);
                pendingReadState.init(securityParameters);
            } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                e.printStackTrace();
                throw new FatalAlertException(AlertDescription.INTERNAL_ERROR);
            }

            // send client ChangeCipherSpec message
            /*
                Immediately after sending this message, the sender MUST instruct the
                record layer to make the write pending state the write active state.
             */
            ChangeCipherSpecMessage changeCipherSpec = new ChangeCipherSpecMessage();
            recordLayer.putNextOutgoingMessage(changeCipherSpec);

            // make the pending write state the current write state
            recordLayer.updateWriteState(pendingWriteState);
            currWriteState = pendingWriteState;

            // create client Finished message
            Finished clientFinished = Finished.createClientFinishedMessage(masterSecret,
                    clientHello, serverHello, certificate, serverHelloDone, clientKeyExchange);
            System.out.println("client finished generated by client: " + DatatypeConverter.printHexBinary(clientFinished.getContent()));

            // since we have updated the recordLayer's write state, it should encrypt this for us
            System.out.println("Sending client Finished...");
            recordLayer.putNextOutgoingMessage(clientFinished);
            System.out.println("Sent client Finished.");

            // receive server ChangeCipherSpec message
            /*
                Reception
                of this message causes the receiver to instruct the record layer to
                mmediately copy the read pending state into the read current state.
             */
            System.out.println("Waiting for server ChangeCipherSpec...");
            recordLayer.getNextIncomingMessage().asChangeCipherSpecMessage();
            System.out.println("Received server ChangeCipherSpec");

            // make the pending read state the current read state
            recordLayer.updateReadState(pendingReadState);
            currReadState = pendingReadState;

            // receive server Finished message
            System.out.println("Waiting for server Finished...");
            Finished serverFinished = (Finished) recordLayer.getNextIncomingMessage().asHandshakeMessage(HandshakeType.FINISHED);
            System.out.println("Received server Finished.");

            // verify server Finished message
            System.out.println("Verifying server Finished...");
            Finished serverFinishedVerify = Finished.createServerFinishedMessage(masterSecret,
                    clientHello, serverHello, certificate, serverHelloDone, clientKeyExchange, clientFinished);
            if (!Arrays.equals(serverFinished.getContent(), serverFinishedVerify.getContent()))
                throw new FatalAlertException(AlertDescription.DECRYPT_ERROR);
            System.out.println("Verified server Finished.");

            System.out.println("Handshake completed.");

            // send application data
            ApplicationData data = new ApplicationData("hello, world".getBytes());
            recordLayer.putNextOutgoingMessage(data);

            return recordLayer;
        } catch (FatalAlertException e) {
            recordLayer.putNextOutgoingMessage(AlertMessage.fatal(e.getAlertDescription()));
            e.printStackTrace();
            throw new RuntimeException();
        }
    }

//    public boolean uploadFile(Path file) throws IOException {
//        // ensure file exists and is a regular file
//        if (!Files.exists(file)) throw new FileNotFoundException();
//        if (!Files.isRegularFile(file)) throw new IllegalArgumentException();
//
//        // prepare file metadata
//        Metadata md = Metadata.get(file);
//
//        // create FileChannel
//        FileChannel content = FileChannel.open(file);
//
//        // open socket to serverAddress
//        SocketChannel sc = SocketChannel.open(serverAddress);
//
//        // create tcp buffer
//        ByteBuffer buffer = ByteBuffer.allocate(sc.socket().getSendBufferSize());
//
////        // send metadata
////        ChannelWriter.writeBytes(md.toReadableByteChannel(), sc, buffer);
////
////        // send content
////        ChannelWriter.writeBytes(content, sc, buffer);
//
//        // fluent interface implementation
//        ChannelWriter.get(sc, buffer)
//                .write(md.toReadableByteChannel())
//                .write(content);
//
//        // test receive confirmation
//        buffer.clear();
//        sc.read(buffer);
//        buffer.flip();
//        long success = buffer.getLong();
//
//        // close socket
//        sc.close();
//
//        // return true for success
//        return success == UPLOAD_SUCCESS;
//    }

}


