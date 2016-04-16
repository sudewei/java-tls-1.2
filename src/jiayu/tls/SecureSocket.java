//package jiayu.tls;
//
//import javax.crypto.BadPaddingException;
//import javax.crypto.IllegalBlockSizeException;
//import javax.crypto.NoSuchPaddingException;
//import javax.xml.bind.DatatypeConverter;
//import java.io.ByteArrayInputStream;
//import java.io.IOException;
//import java.net.Socket;
//import java.security.*;
//import java.security.cert.CertificateException;
//import java.security.cert.CertificateExpiredException;
//import java.security.cert.CertificateFactory;
//import java.security.cert.X509Certificate;
//import java.util.Arrays;
//
//import static jiayu.Client.CLIENT_VERSION;
//
//@SuppressWarnings("Duplicates")
//public class SecureSocket {
//    private static final CipherSuite[] SUPPORTED_CIPHER_SUITES = new CipherSuite[]{CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256};
//
//    private final Socket socket;
//    private final RecordLayer recordLayer;
//
//    private X509Certificate caCert;
//
//    private SecurityParameters securityParameters;
//    private ConnectionState current;
//    private ConnectionState pending;
//
//
//    public SecureSocket(String host, int port) throws IOException {
//        socket = new Socket(host, port);
//        recordLayer = RecordLayer.getInstance(socket);
//
//        securityParameters = new SecurityParameters(ConnectionEnd.CLIENT);
//
//        connectSecured();
//    }
//
//    private void connectSecured() throws IOException {
//        // send client hello
//        System.out.print("Sending client hello... ");
//        System.out.flush();
//        ClientHello clientHello = new ClientHello(SUPPORTED_CIPHER_SUITES);
//        recordLayer.putNextOutgoingMessage(clientHello);
//        System.out.println("Done.");
//
//        securityParameters.setClientRandom(clientHello.getRandom().toBytes());
//
//        // receive server hello
//        System.out.print("Waiting for ServerHello... ");
//        System.out.flush();
//        try {
//            ServerHello serverHello = (ServerHello) recordLayer.getNextIncomingMessage()
//                    .asHandshakeMessage(HandshakeType.SERVER_HELLO);
//            System.out.println("Received.");
//
//            securityParameters.setCipherSuite(serverHello.getCipherSuite());
//            securityParameters.setServerRandom(serverHello.getRandom().toBytes());
//
//            // receive server certificate
//            System.out.print("Waiting for Certificate... ");
//            System.out.flush();
//            Certificate certificate = (Certificate) recordLayer.getNextIncomingMessage()
//                    .asHandshakeMessage(HandshakeType.CERTIFICATE);
//            System.out.println("Received.");
//
//
//            // wait for serverhellodone
//            System.out.print("Waiting for ServerHelloDone... ");
//            System.out.flush();
//            ServerHelloDone serverHelloDone = (ServerHelloDone) recordLayer.getNextIncomingMessage()
//                    .asHandshakeMessage(HandshakeType.SERVER_HELLO_DONE);
//            System.out.println("Received.");
//
//            // authenticate server certificate
//            // FIXME: 15/04/2016 authenticates each cert individually instead of as a chain
//            /*
//                I need to check each certificate against the next cert in the certificate list
//                if the certificate is the last ecrt in the certificate list
//                we check it against the cacert instead
//
//                the server cert is always the first certificate in the list
//             */
//            PublicKey serverPublicKey;
//            System.out.println("Authenticating server certificates... ");
//            CertificateList certChain = certificate.getCertificateList();
//            X509Certificate serverCert = null;
//            X509Certificate prev = null;
//            X509Certificate current;
//            try {
//                for (ASN1Cert asn1Cert : certChain.getContents()) {
//                    if (prev == null) {
//                        serverCert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(asn1Cert.getContent()));
//                        System.out.println("Server DN: " + serverCert.getSubjectX500Principal().getName());
//                        serverCert.checkValidity();
//                        prev = serverCert;
//                    } else {
//                        current = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(asn1Cert.getContent()));
//                        System.out.println("Current DN: " + current.getSubjectX500Principal().getName());
//                        current.checkValidity();
//                        prev.verify(current.getPublicKey());
//                    }
//                }
//                assert prev != null;
//                prev.verify(caCert.getPublicKey());
//                serverPublicKey = serverCert.getPublicKey();
//                System.out.println("Authenticated.");
//
//            } catch (CertificateExpiredException e) {
//                throw new FatalAlertException(AlertDescription.CERTIFICATE_EXPIRED);
//            } catch (CertificateException | SignatureException e) {
//                throw new FatalAlertException(AlertDescription.BAD_CERTIFICATE);
//            } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException e) {
//                throw new FatalAlertException(AlertDescription.INTERNAL_ERROR);
//            }
//
//            // generate and send pre-master key
//            CipherSuite selectedCipherSuite = serverHello.getCipherSuite();
//            PremasterSecret premasterSecret;
//            ClientKeyExchange clientKeyExchange;
//            if (selectedCipherSuite.keyExchangeAlgorithm == KeyExchangeAlgorithm.RSA) {
//                premasterSecret = PremasterSecret.newRSAPremasterSecret(CLIENT_VERSION);
//                try {
//                    clientKeyExchange = new ClientKeyExchange(premasterSecret.getEncryptedBytes(serverPublicKey));
//                } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
//                    throw new FatalAlertException(AlertDescription.INTERNAL_ERROR);
//                }
//                recordLayer.putNextOutgoingMessage(clientKeyExchange);
//                System.out.println("Done.");
//                System.out.println("Unencypted premaster secret: " + Arrays.toString(premasterSecret.getBytes()));
//                System.out.println("Premaster secret length: " + premasterSecret.getBytes().length);
//            } else {
//                throw new FatalAlertException(AlertDescription.INTERNAL_ERROR);
//            }
//
//            // send client ChangeCipherSpec message
//            ChangeCipherSpecMessage changeCipherSpec = new ChangeCipherSpecMessage();
//            recordLayer.putNextOutgoingMessage(changeCipherSpec);
//
//            // generate master secret
//            MasterSecret masterSecret;
//            try {
//                masterSecret = MasterSecret.generateMasterSecret(premasterSecret, clientHello, serverHello);
//                System.out.println("Master secret: " + Arrays.toString(masterSecret.getBytes()));
//                System.out.println("Master secret length: " + masterSecret.getBytes().length);
//            } catch (InvalidKeyException | NoSuchAlgorithmException e) {
//                throw new FatalAlertException(AlertDescription.INTERNAL_ERROR);
//            }
//
//            securityParameters.setMasterSecret(masterSecret.getBytes());
//            ConnectionState state;
//            try {
//                state = new ConnectionState(securityParameters);
//            } catch (NoSuchAlgorithmException | InvalidKeyException e) {
//                e.printStackTrace();
//                throw new FatalAlertException(AlertDescription.INTERNAL_ERROR);
//            }
//
//            // create client Finished message
//            Finished clientFinished = Finished.createClientFinishedMessage(masterSecret, clientHello, serverHello, certificate, serverHelloDone, clientKeyExchange);
//            System.out.println("client finished generated by client: " + DatatypeConverter.printHexBinary(clientFinished.getContent()));
//
//            // encrypt client Finished message
//            try {
//                GenericBlockCipher encryptedClientFinished = GenericBlockCipher.encrypt(state, clientFinished.getContent());
//                EncryptedFinished encryptedFinished = new EncryptedFinished(encryptedClientFinished);
//
//                System.out.println(DatatypeConverter.printHexBinary(encryptedFinished.getContent()));
//
//                recordLayer.putNextOutgoingMessage(encryptedFinished);
//            } catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException | IllegalBlockSizeException | InvalidAlgorithmParameterException | BadPaddingException e) {
//                e.printStackTrace();
//                throw new FatalAlertException(AlertDescription.INTERNAL_ERROR);
//            }
//
//
////            recordLayer.putNextOutgoingMessage(clientFinished);
//
//        } catch (FatalAlertException e) {
//            e.printStackTrace();
//        }
//    }
//}
