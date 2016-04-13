package jiayu.tls;

import jiayu.tls.filetransfer.Checksum;
import jiayu.tls.filetransfer.Metadata;
import jiayu.tls.protocol.RecordLayer;
import jiayu.tls.protocol.handshake.CipherSuite;
import jiayu.tls.protocol.handshake.ClientHello;
import jiayu.tls.protocol.handshake.UnexpectedMessageException;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.*;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class SecStore {
    // magic number for acknowledging successful upload
    private static final long UPLOAD_SUCCESS = 6584997751L;

    private final ServerSocketChannel ssc;
    private Path destDir;

    // should this be in memory?
    private PrivateKey serverkey;

    private byte[] serverCert;

    private CipherSuite preferredCipherSuite;

    public static void main(String[] args) {
        try {
            SecStore server = new SecStore(new InetSocketAddress("10.12.17.118", 4321), Paths.get(args[0]));
            server.setServerCert(Paths.get(args[1]));
            server.listen();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public SecStore(SocketAddress addr) throws IOException {
        ssc = ServerSocketChannel.open().bind(addr);
    }

    public SecStore(SocketAddress addr, Path destDir) throws IOException {
        this(addr);
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

    public void listen() throws IOException {
        if (destDir == null) throw new IllegalStateException("No destination directory set");

        while (true) {
            receiveFile(ssc.accept());
        }
    }

    public void listen(Handler handler) throws IOException {
        handler.handle(ssc.accept());

    }

    private void receiveFile(SocketChannel sc) throws IOException {
        // receive metadata
        Metadata md = Metadata.readFrom(sc);
        System.out.println("Received MD5 hash:   " + md.getMD5Hash().toHexString());

        // create output file and channel
        Path outputFile = destDir.resolve(md.getFileName());
        FileChannel fc = FileChannel.open(outputFile, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);

        // create tcp buffer
        ByteBuffer buffer = ByteBuffer.allocate(sc.socket().getReceiveBufferSize());

        // receive content and write to output file
        ChannelWriter.writeBytes(sc, fc, buffer, md.getSize());

        // calculate md5 hash of output file
        Checksum md5 = Checksum.getMD5Checksum(outputFile);
        System.out.println("Calculated MD5 hash: " + md5.toHexString());

        // compare checksums and send result
        buffer.clear();
        if (md5.compareTo(md.getMD5Hash())) {
            System.out.println("File verified.");
            buffer.putLong(UPLOAD_SUCCESS);
            buffer.flip();
        } else {
            System.out.println("File verification failed.");
            buffer.putLong(0);
            buffer.flip();
        }
        sc.write(buffer);

        // close socket
        sc.close();
    }

    public void receiveConnectionSecured(SocketChannel sc) throws IOException {
        if (serverCert == null) throw new IllegalStateException();

        RecordLayer recordLayer = RecordLayer.getInstance(sc);

        ByteBuffer sndBuf = ByteBuffer.allocate(sc.socket().getSendBufferSize());
        ByteBuffer rcvBuf = ByteBuffer.allocate(sc.socket().getReceiveBufferSize());
        ChannelWriter cw = ChannelWriter.get(sc, sndBuf);

        // receive client hello
        System.out.print("Waiting for ClientHello... ");
        ClientHello clientHello;
        try {
            clientHello = ClientHello.interpret(recordLayer.getNextIncomingMessage());
            System.out.println("Received.");
            System.out.println(clientHello);
        } catch (UnexpectedMessageException e) {
//            cw.write(Alert.unexpectedMessageAlert());
            sc.close();
//            return;
        }

//        // choose cipher suite
//        CipherSuite selectedCipherSuite = clientHello.getCipherSuites().contains(preferredCipherSuite)
//                ? preferredCipherSuite
//                : clientHello.getCipherSuites().get(0);
//        int sessionId = new SecureRandom().nextInt();
//
//        // send server hello
//        System.out.print("Sending ServerHello... ");
//        ServerHello serverHello = new ServerHello(sessionId, selectedCipherSuite);
//        cw.write(serverHello);
//        System.out.println("Done.");
//
//        // send server serverCert
//        System.out.print("Sending Certificate... ");
//        Certificate certificate = new Certificate(this.serverCert);
//        cw.write(certificate);
//        System.out.println("Done.");
//
//        // send server hello done
//        System.out.print("Sending ServerHelloDone... ");
//        cw.write(new ServerHelloDone());
//        System.out.println("Done.");
//
//        // receive ClientKeyExchange
//        System.out.print("Receiving ClientKeyExchange... ");
//        ClientKeyExchange clientKeyExchange = ClientKeyExchange.tryToReadFrom(sc);
//        System.out.println("Done.");
//
//        // read premaster secret
//        PremasterSecret premasterSecret = new PremasterSecret(clientKeyExchange.getEncryptedPremasterSecret());
//        try {
//            premasterSecret.decrypt(serverkey, clientHello.getClientVersion());
//            System.out.println("Decrypted premaster secret: " + Arrays.toString(premasterSecret.getBytes()));
//        } catch (BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException | InvalidKeyException | NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        }
//
//        // receive client ChangeCipherSpec
//        ChangeCipherSpec.tryToReadFrom(sc);
//
//        // generate master secret
//        MasterSecret masterSecret;
//        try {
//            masterSecret = MasterSecret.generateMasterSecret(premasterSecret, clientHello, serverHello);
//            System.out.println("Master secret: " + Arrays.toString(masterSecret.getBytes()));
//        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        }
//
//        // TODO: 11/04/2016 receive client Finished
//
//        // TODO: 11/04/2016 send server ChangeCipherSpec
//
//        // TODO: 11/04/2016 send server Finished

    }

    @FunctionalInterface
    interface Handler {
        void handle(SocketChannel sc) throws IOException;
    }
}
