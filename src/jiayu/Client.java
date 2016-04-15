package jiayu;

import jiayu.tls.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class Client {
    public static final short CLIENT_VERSION = 0x0303;

    // magic number for acknowledging successful upload
    private static final long UPLOAD_SUCCESS = 6584997751L;
    private static final CipherSuite[] SUPPORTED_CIPHER_SUITES = new CipherSuite[]{CipherSuite.TLS_RSA_WITH_AES_128_ECB_SHA256, CipherSuite.TLS_RSA_WITH_RSA_1024_ECB_SHA256};

    private X509Certificate caCert;

    private int sessionId;

    public void setCACertificate(Path caCert) throws IOException, CertificateException {
        if (!Files.exists(caCert)) throw new FileNotFoundException();
        if (!Files.isRegularFile(caCert)) throw new IllegalArgumentException();

        this.caCert = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(Files.newInputStream(caCert));
    }

    public void connectSecured(String serverAddress, int port) throws IOException {
        Socket socket = new Socket(serverAddress, port);

        RecordLayer recordLayer = RecordLayer.getInstance(socket);

//        ByteBuffer sndBuf = ByteBuffer.allocate(sc.socket().getSendBufferSize());
//        ByteBuffer rcvBuf = ByteBuffer.allocate(sc.socket().getReceiveBufferSize());
//        ChannelWriter cw = ChannelWriter.get(sc, sndBuf);

        // send client hello
        System.out.print("Sending client hello... ");
        System.out.flush();
        ClientHello clientHello = new ClientHello(SUPPORTED_CIPHER_SUITES);
        recordLayer.putNextOutgoingMessage(clientHello);
        System.out.println("Done.");

        // receive server hello
        System.out.print("Waiting for ServerHello... ");
        System.out.flush();
        try {
            ServerHello serverHello = (ServerHello) recordLayer.getNextIncomingMessage()
                    .asHandshakeMessage(HandshakeType.SERVER_HELLO);
            System.out.println("Received.");


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

                System.out.println("Authenticated.");

                // generate and send pre-master key
                CipherSuite selectedCipherSuite = serverHello.getCipherSuite();
                PremasterSecret premasterSecret;
                ClientKeyExchange clientKeyExchange;
                if (selectedCipherSuite.keyExchangeAlgorithm.equals("RSA")) {
                    premasterSecret = PremasterSecret.newRSAPremasterSecret(CLIENT_VERSION);
                    clientKeyExchange = new ClientKeyExchange(premasterSecret.getEncryptedBytes(serverCert));
                    recordLayer.putNextOutgoingMessage(clientKeyExchange);
                    System.out.println("Done.");
                    System.out.println("Unencypted premaster secret: " + Arrays.toString(premasterSecret.toBytes()));
                    System.out.println("Premaster secret length: " + premasterSecret.toBytes().length);
                } else {
                    throw new FatalAlertException(AlertDescription.INTERNAL_ERROR);
                }
            } catch (CertificateExpiredException e) {
                throw new FatalAlertException(AlertDescription.CERTIFICATE_EXPIRED);
            } catch (CertificateException | SignatureException e) {
                throw new FatalAlertException(AlertDescription.BAD_CERTIFICATE);
            } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
                throw new FatalAlertException(AlertDescription.INTERNAL_ERROR);
            }

        } catch (FatalAlertException e) {
            e.printStackTrace();
        }


//            PremasterSecret premasterSecret;
//            try {
//                System.out.print("Generating pre-master key... ");
//                // todo: for CP-1, generate a new RSA keypair and send the public key encrypted by the server key
//
//
//                // send ClientKeyExchange
//                System.out.print("Sending ClientKeyExchange... ");
//                ClientKeyExchange clientKeyExchange = new ClientKeyExchange(premasterSecret.getEncryptedBytes(serverCert));
//                cw.write(clientKeyExchange);
//                System.out.println("Done.");
//            } catch (NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | NoSuchPaddingException | IllegalBlockSizeException e) {
//                System.out.println("Failed! Reason: " + e.getMessage());
//                cw.write(AlertMessage.fatal(AlertMessage.AlertDescription.INTERNAL_ERROR));
//                sc.close();
//                return;
//            }
//
//            // send client ChangeCipherSpecMessage
//            cw.write(new ChangeCipherSpecMessage().toReadableByteChannel());
//
//            // generate master secret
//            MasterSecret masterSecret;
//            try {
//                masterSecret = MasterSecret.generateMasterSecret(premasterSecret, clientHello, serverHello);
//                System.out.println("Master secret: " + Arrays.toString(masterSecret.toBytes()));
//                System.out.println("Master secret length: " + masterSecret.toBytes().length);
//            } catch (InvalidKeyException | NoSuchAlgorithmException e) {
//                e.printStackTrace();
//            }
//
//            // TODO: 11/04/2016 send client Finished
//
//
//            // TODO: 11/04/2016 receive server ChangeCipherSpecMessage
//
//            // TODO: 11/04/2016 receive server Finished
//
//        } catch (UnexpectedMessageException e) {
//            cw.write(AlertMessage.fatal(AlertMessage.AlertDescription.UNEXPECTED_MESSAGE));
//            sc.close();
//        }
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


