package jiayu;

import jiayu.tls.*;
import jiayu.tls.filetransfer.Metadata;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class Client {
    public static final short CLIENT_VERSION = 0x0303;

    // magic number for acknowledging successful upload
    private static final long UPLOAD_SUCCESS = 6584997751L;
    private static final CipherSuite[] SUPPORTED_CIPHER_SUITES = new CipherSuite[]{CipherSuite.TLS_RSA_WITH_AES_128_ECB_SHA256, CipherSuite.TLS_RSA_WITH_RSA_1024_ECB_SHA256};

    private final SocketAddress serverAddress;
    private X509Certificate caCert;

    private int sessionId;

    public static void main(String[] args) throws IOException {
        Path file = Paths.get(args[0]);

        Client client = new Client(new InetSocketAddress("192.168.198.128", 4321));
        boolean success = client.uploadFile(file);
        if (success) System.out.println("File uploaded successfully.");
        else System.out.println("File upload failed, please try again.");
    }

    public Client(SocketAddress serverAddress) {
        this.serverAddress = serverAddress;
    }

    public void setCACertificate(Path caCert) throws IOException, CertificateException {
        if (!Files.exists(caCert)) throw new FileNotFoundException();
        if (!Files.isRegularFile(caCert)) throw new IllegalArgumentException();

        this.caCert = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(Files.newInputStream(caCert));
    }

    public void connectSecured() throws IOException {
        SocketChannel sc = SocketChannel.open(serverAddress);
        RecordLayer recordLayer = RecordLayer.getInstance(sc);

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
            ServerHello serverHello = recordLayer.getNextIncomingMessage().asHandshakeMessage().asServerHello();
            System.out.println("Received.");
        } catch (FatalAlertException e) {
            e.printStackTrace();
        }

        System.out.print("Waiting for Certificate... ");
        System.out.flush();
        try {
            Certificate certificate = recordLayer.getNextIncomingMessage().asHandshakeMessage().asCertificate();
            System.out.println("Received.");
        } catch (FatalAlertException e) {
            e.printStackTrace();
        }

        System.out.print("Waiting for ServerHelloDone... ");
        System.out.flush();
        try {
            ServerHelloDone serverHelloDone =
                    recordLayer.getNextIncomingMessage().asHandshakeMessage().asServerHelloDone();
            System.out.println("Received.");
        } catch (FatalAlertException e) {
            e.printStackTrace();
        }

//        try {
//            // receive server hello
//            System.out.print("Waiting for server hello... ");
//            ServerHello serverHello;
//            serverHello = ServerHello.tryToReadFrom(sc);
//            System.out.println("Received");
//
//            // receive server certificate
//            System.out.print("Waiting for server certificate... ");
//            Certificate certificate = Certificate.tryToReadFrom(sc);
//            System.out.println("Received.");
//            System.out.println(new String(certificate.getCertificateList()));
//
//            // wait for server hello done
//            System.out.print("Waiting for ServerHelloDone... ");
//            ServerHelloDone serverHelloDone = ServerHelloDone.tryToReadFrom(sc);
//            System.out.println("Received.");
//
//            CipherSuite selectedCipherSuite = serverHello.getCipherSuite();
//
//            // authenticate server certificate
//            System.out.print("Authenticating server certificate... ");
//            X509Certificate serverCert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certificate.getCertificateList()));
//            try {
//                serverCert.checkValidity();
//                serverCert.verify(caCert.getPublicKey());
//                System.out.println("Authenticated.");
//            } catch (CertificateExpiredException | CertificateNotYetValidException e) {
//                System.out.println("Failed! Reason: " + e.getMessage());
////                cw.write(AlertMessage.fatal(AlertMessage.AlertDescription.CERTIFICATE_EXPIRED));
////                sc.close();
////                return;
//            } catch (NoSuchAlgorithmException | NoSuchProviderException | SignatureException | InvalidKeyException e) {
//                System.out.println("Failed! Reason: " + e.getMessage());
////                cw.write(AlertMessage.fatal(AlertMessage.AlertDescription.BAD_CERTIFICATE));
////                sc.close();
////                return;
//            }
//
//            // generate and send pre-master key
//            PremasterSecret premasterSecret;
//            try {
//                System.out.print("Generating pre-master key... ");
//
//                // todo: for CP-1, generate a new RSA keypair and send the public key encrypted by the server key
//
//                if (selectedCipherSuite.keyExchangeAlgorithm.equals("RSA")) {
//                    premasterSecret = PremasterSecret.newRSAPremasterSecret(CLIENT_VERSION);
//                    System.out.println("Done.");
//                    System.out.println("Unencypted premaster secret: " + Arrays.toString(premasterSecret.toBytes()));
//                    System.out.println("Premaster secret length: " + premasterSecret.toBytes().length);
//                } else {
//                    System.out.println("Failed! Reason: Unsupported key exchange algorithm");
//                    cw.write(AlertMessage.fatal(AlertMessage.AlertDescription.HANDSHAKE_FAILURE));
//                    sc.close();
//                    return;
//                }
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

    public boolean uploadFile(Path file) throws IOException {
        // ensure file exists and is a regular file
        if (!Files.exists(file)) throw new FileNotFoundException();
        if (!Files.isRegularFile(file)) throw new IllegalArgumentException();

        // prepare file metadata
        Metadata md = Metadata.get(file);

        // create FileChannel
        FileChannel content = FileChannel.open(file);

        // open socket to serverAddress
        SocketChannel sc = SocketChannel.open(serverAddress);

        // create tcp buffer
        ByteBuffer buffer = ByteBuffer.allocate(sc.socket().getSendBufferSize());

//        // send metadata
//        ChannelWriter.writeBytes(md.toReadableByteChannel(), sc, buffer);
//
//        // send content
//        ChannelWriter.writeBytes(content, sc, buffer);

        // fluent interface implementation
        ChannelWriter.get(sc, buffer)
                .write(md.toReadableByteChannel())
                .write(content);

        // test receive confirmation
        buffer.clear();
        sc.read(buffer);
        buffer.flip();
        long success = buffer.getLong();

        // close socket
        sc.close();

        // return true for success
        return success == UPLOAD_SUCCESS;
    }

}


