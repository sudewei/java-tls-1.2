package jiayu.tls;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;

@SuppressWarnings("Duplicates")
public class SecureSocket {
    public static final short CLIENT_VERSION = 0x0303;
    private static final CipherSuite[] SUPPORTED_CIPHER_SUITES = new CipherSuite[]{CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256};

    private Socket socket;
    private RecordLayer recordLayer;

    SecureSocketInputStream in;
    SecureSocketOutputStream out;

    private HashSet<X509Certificate> caCerts;

    SecureSocket(RecordLayer recordLayer) {
        this.recordLayer = recordLayer;
    }

    public SecureSocket() {
    }

    public SecureSocket(String host, int port, Path caCert) throws IOException, CertificateException {
        addCACertificate(caCert);
        connectSecured(host, port);
    }

    public void addCACertificate(X509Certificate caCert) {
        if (caCerts == null) caCerts = new HashSet<>();

        caCerts.add(caCert);
    }

    public void addCACertificate(Path caCert) throws IOException, CertificateException {
        if (!Files.exists(caCert)) throw new FileNotFoundException();
        if (!Files.isRegularFile(caCert)) throw new IllegalArgumentException();

        if (caCerts == null) caCerts = new HashSet<>();

        caCerts.add((X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(Files.newInputStream(caCert)));
    }

    public void connectSecured(String host, int port) throws IOException {
        if (caCerts == null || caCerts.isEmpty()) throw new IllegalStateException("no CA certs specified");

        socket = new Socket(host, port);

        SecurityParameters currSecParams = new SecurityParameters(ConnectionEnd.CLIENT);

        ConnectionState currReadState = new ConnectionState();
        ConnectionState currWriteState = new ConnectionState();

        try {
            System.out.println("Initialising current read and write states...");
            currReadState.init(currSecParams);
            currWriteState.init(currSecParams);
        System.out.println("Current cipher suite: " + currSecParams.getCipherSuite().name());
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }

        RecordLayer recordLayer = RecordLayer.getInstance(socket, currReadState, currWriteState);

        SecurityParameters securityParameters = new SecurityParameters(ConnectionEnd.CLIENT);
        ConnectionState pendingReadState = new ConnectionState();
        ConnectionState pendingWriteState = new ConnectionState();

        // send client hello
        System.out.println("Sending ClientHello... ");
        ClientHello clientHello = new ClientHello(SUPPORTED_CIPHER_SUITES);
        recordLayer.putNextOutgoingMessage(clientHello);

        securityParameters.setClientRandom(clientHello.getRandom().toBytes());

        // receive server hello
        System.out.println("Waiting for ServerHello... ");
        try {
            ServerHello serverHello = (ServerHello) recordLayer.getNextIncomingMessage()
                    .asHandshakeMessage(HandshakeType.SERVER_HELLO);

            securityParameters.setCipherSuite(serverHello.getCipherSuite());
            securityParameters.setServerRandom(serverHello.getRandom().toBytes());

            // receive server certificate
            System.out.println("Waiting for server Certificate... ");
            System.out.flush();
            Certificate certificate = (Certificate) recordLayer.getNextIncomingMessage()
                    .asHandshakeMessage(HandshakeType.CERTIFICATE);


            // wait for serverhellodone
            System.out.println("Waiting for ServerHelloDone... ");
            System.out.flush();
            ServerHelloDone serverHelloDone = (ServerHelloDone) recordLayer.getNextIncomingMessage()
                    .asHandshakeMessage(HandshakeType.SERVER_HELLO_DONE);

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
            if (certChain.getContents().isEmpty()) throw new FatalAlertException(AlertDescription.BAD_CERTIFICATE);
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
                        prev = current;
                    }
                }
                assert prev != null;
                boolean verified = false;
                for (X509Certificate caCert : caCerts) {
                    try {
                        prev.verify(caCert.getPublicKey());
                        verified = true;
                        break;
                    } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException ignored) {
                    }
                }
                if (!verified) throw new FatalAlertException(AlertDescription.BAD_CERTIFICATE);
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
            System.out.println("Generating premaster secret...");
            CipherSuite selectedCipherSuite = serverHello.getCipherSuite();
            PremasterSecret premasterSecret;
            ClientKeyExchange clientKeyExchange;
            if (selectedCipherSuite.keyExchangeAlgorithm == KeyExchangeAlgorithm.RSA) {
                premasterSecret = PremasterSecret.newRSAPremasterSecret(CLIENT_VERSION);
                System.out.println("Premaster secret: " + DatatypeConverter.printBase64Binary(premasterSecret.getBytes()));
                try {
                    clientKeyExchange = new ClientKeyExchange(premasterSecret.getEncryptedBytes(serverPublicKey));
                } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
                    throw new FatalAlertException(AlertDescription.INTERNAL_ERROR);
                }
                System.out.println("Sending ClientKeyExchange...");
                recordLayer.putNextOutgoingMessage(clientKeyExchange);
            } else {
                throw new FatalAlertException(AlertDescription.INTERNAL_ERROR);
            }

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
            try {
                System.out.println("Initialising pending read and write states...");
                pendingWriteState.init(securityParameters);
                pendingReadState.init(securityParameters);
                System.out.println("Pending cipher suite: " + securityParameters.getCipherSuite().name());
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
            System.out.println("Sending client ChangeCipherSpec...");
            recordLayer.putNextOutgoingMessage(changeCipherSpec);
            System.out.println("Made pending write state current.");
            // make the pending write state the current write state
            recordLayer.updateWriteState(pendingWriteState);
            currWriteState = pendingWriteState;

            // create client Finished message
            System.out.println("Generating client Finished...");
            Finished clientFinished = Finished.createClientFinishedMessage(masterSecret,
                    clientHello, serverHello, certificate, serverHelloDone, clientKeyExchange);

            // since we have updated the recordLayer's write state, it should encrypt this for us
            System.out.println("Sending client Finished...");
            recordLayer.putNextOutgoingMessage(clientFinished);

            // receive server ChangeCipherSpec message
            /*
                Reception
                of this message causes the receiver to instruct the record layer to
                mmediately copy the read pending state into the read current state.
             */
            System.out.println("Waiting for server ChangeCipherSpec...");
            recordLayer.getNextIncomingMessage().asChangeCipherSpecMessage();
            System.out.println("Made pending read state current.");
            // make the pending read state the current read state
            recordLayer.updateReadState(pendingReadState);
            currReadState = pendingReadState;

            // receive server Finished message
            System.out.println("Waiting for server Finished...");
            Finished serverFinished = (Finished) recordLayer.getNextIncomingMessage().asHandshakeMessage(HandshakeType.FINISHED);

            // verify server Finished message
            System.out.println("Verifying server Finished...");
            Finished serverFinishedVerify = Finished.createServerFinishedMessage(masterSecret,
                    clientHello, serverHello, certificate, serverHelloDone, clientKeyExchange, clientFinished);
            if (!Arrays.equals(serverFinished.getContent(), serverFinishedVerify.getContent()))
                throw new FatalAlertException(AlertDescription.DECRYPT_ERROR);

            System.out.println("Handshake complete.");

            this.recordLayer = recordLayer;
        } catch (FatalAlertException e) {
            recordLayer.putNextOutgoingMessage(AlertMessage.fatal(e.getAlertDescription()));
            e.printStackTrace();
            throw new RuntimeException();
        }
    }

    public OutputStream getOutputStream() {
        if (recordLayer == null) throw new IllegalStateException("not connected yet");

        if (out == null) out = new SecureSocketOutputStream(recordLayer);
        return out;
    }

    public SecureSocketInputStream getInputStream() {
        if (recordLayer == null) throw new IllegalStateException("not connected yet");

        if (in == null) in = new SecureSocketInputStream(recordLayer);
        return in;
    }

    public void close() throws IOException {
        in.close();
        out.close();

        socket.close();
    }
}
