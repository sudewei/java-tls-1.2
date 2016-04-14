package jiayu;

import jiayu.tls.*;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.NotDirectoryException;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

public class SecStore {
    // magic number for acknowledging successful upload
    private static final long UPLOAD_SUCCESS = 6584997751L;

    private final ServerSocket sc;
    private Path destDir;

    // should this be in memory?
    private PrivateKey serverkey;

    private byte[] serverCert;

    private CipherSuite preferredCipherSuite;

    public SecStore(int port) throws IOException {
        sc = new ServerSocket(port);
    }

    public SecStore(int port, Path destDir) throws IOException {
        this(port);
        setDestinationDirectory(destDir);
    }

    public void setDestinationDirectory(Path dest) throws NotDirectoryException {
        if (!Files.isDirectory(dest)) throw new NotDirectoryException(dest.toString());

        this.destDir = dest;
    }

    public void setPreferredCipherSuite(CipherSuite preferredCipherSuite) {
        this.preferredCipherSuite = preferredCipherSuite;
    }

    public void setServerKey(Path keyFile) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        if (!Files.exists(keyFile)) throw new FileNotFoundException();
        if (!Files.isRegularFile(keyFile)) throw new IllegalArgumentException();

        byte[] keyBytes = Files.readAllBytes(keyFile);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        serverkey = KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    }

    public void setServerCert(Path cert) throws IOException {
        if (!Files.exists(cert)) throw new FileNotFoundException();

        serverCert = Files.readAllBytes(cert);
    }

//    public void listen() throws IOException {
//        if (destDir == null) throw new IllegalStateException("No destination directory set");
//
//        while (true) {
//            receiveFile(ssc.accept());
//        }
//    }

    public void listen(Handler handler) throws IOException {
        while (true) handler.handle(sc.accept());

    }

//    private void receiveFile(SocketChannel sc) throws IOException {
//        // receive metadata
//        Metadata md = Metadata.readFrom(sc);
//        System.out.println("Received MD5 hash:   " + md.getMD5Hash().toHexString());
//
//        // create output file and channel
//        Path outputFile = destDir.resolve(md.getFileName());
//        FileChannel fc = FileChannel.open(outputFile, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
//
//        // create tcp buffer
//        ByteBuffer buffer = ByteBuffer.allocate(sc.socket().getReceiveBufferSize());
//
//        // receive content and write to output file
//        ChannelWriter.writeBytes(sc, fc, buffer, md.getSize());
//
//        // calculate md5 hash of output file
//        Checksum md5 = Checksum.getMD5Checksum(outputFile);
//        System.out.println("Calculated MD5 hash: " + md5.toHexString());
//
//        // compare checksums and send result
//        buffer.clear();
//        if (md5.compareTo(md.getMD5Hash())) {
//            System.out.println("File verified.");
//            buffer.putLong(UPLOAD_SUCCESS);
//            buffer.flip();
//        } else {
//            System.out.println("File verification failed.");
//            buffer.putLong(0);
//            buffer.flip();
//        }
//        sc.write(buffer);
//
//        // close socket
//        sc.close();
//    }

    public void receiveConnectionSecured(Socket socket) throws IOException {
        if (serverCert == null) throw new IllegalStateException();

        RecordLayer recordLayer = RecordLayer.getInstance(socket);

        // receive client hello
        System.out.print("Waiting for ClientHello... ");
        System.out.flush();
        ClientHello clientHello;
        try {
            clientHello = recordLayer.getNextIncomingMessage().asHandshakeMessage().asClientHello();
            System.out.println("Received.");
            System.out.println(clientHello);
        } catch (FatalAlertException e) {
//            cw.write(AlertMessage.unexpectedMessageAlert());
            System.out.println("Unexpected message!");

            e.printStackTrace();

            socket.close();
            return;
        }

        // choose cipher suite
        System.out.print("Choosing cipher suite... ");
        System.out.flush();
        CipherSuite selectedCipherSuite = Arrays.asList(clientHello.getCipherSuites()).contains(preferredCipherSuite)
                ? preferredCipherSuite
                : clientHello.getCipherSuites()[0];
        System.out.println("Selected cipher suite: " + selectedCipherSuite.name());

        // send server hello
        System.out.print("Sending ServerHello... ");
        System.out.flush();
        ServerHello serverHello = new ServerHello(selectedCipherSuite);
        recordLayer.putNextOutgoingMessage(serverHello);
        System.out.println("Done.");

        // send server serverCert
        System.out.print("Sending Certificate... ");
        System.out.flush();
        Certificate certificate = new Certificate(new ASN1Cert(this.serverCert));
        recordLayer.putNextOutgoingMessage(certificate);
        System.out.println("Done.");

        // send server hello done
        System.out.print("Sending ServerHelloDone... ");
        System.out.flush();
        ServerHelloDone serverHelloDone = new ServerHelloDone();
        recordLayer.putNextOutgoingMessage(serverHelloDone);
        System.out.println("Done.");

//        // receive ClientKeyExchange
//        System.out.print("Receiving ClientKeyExchange... ");
//        ClientKeyExchange clientKeyExchange = ClientKeyExchange.tryToReadFrom(sc);
//        System.out.println("Done.");
//
//        // read premaster secret
//        PremasterSecret premasterSecret = new PremasterSecret(clientKeyExchange.getEncryptedPremasterSecret());
//        try {
//            premasterSecret.decrypt(serverkey, clientHello.getClientVersion());
//            System.out.println("Decrypted premaster secret: " + Arrays.toString(premasterSecret.toBytes()));
//        } catch (BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException | InvalidKeyException | NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        }
//
//        // receive client ChangeCipherSpecMessage
//        ChangeCipherSpecMessage.tryToReadFrom(sc);
//
//        // generate master secret
//        MasterSecret masterSecret;
//        try {
//            masterSecret = MasterSecret.generateMasterSecret(premasterSecret, clientHello, serverHello);
//            System.out.println("Master secret: " + Arrays.toString(masterSecret.toBytes()));
//        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        }
//
//        // TODO: 11/04/2016 receive client Finished
//
//        // TODO: 11/04/2016 send server ChangeCipherSpecMessage
//
//        // TODO: 11/04/2016 send server Finished

    }

    @FunctionalInterface
    public interface Handler {
        void handle(Socket socket) throws IOException;
    }
}
