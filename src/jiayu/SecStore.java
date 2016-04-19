package jiayu;

import jiayu.tls.SecureServerSocket;
import jiayu.tls.SecureSocket;
import jiayu.tls.SecureSocketInputStream;
import jiayu.tls.filetransfer.Metadata;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class SecStore {
    private Path destDir;
    private SecureServerSocket sss;

    public SecStore() throws IOException {
        sss = new SecureServerSocket();
        sss.setServerCert(Paths.get("misc/certs/servercert.crt"));
        try {
            sss.setServerKey(Paths.get("misc/certs/serverkey.der"));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException();
        }
    }

    public void setDestDir(Path path) {
        destDir = path;
    }

    public void bind(int port) throws IOException {
        sss.bind(port);
    }

    public void listen() throws IOException {
        receiveFile(sss.acceptSecured());
    }

    public void listen(Handler handler) throws IOException {
        handler.handle(sss.acceptSecured());
    }

    public void receiveBytes(byte[] bytes) {

    }

    public void receiveFile(SecureSocket ss) throws IOException {
        if (destDir == null) throw new IllegalStateException("no destination directory set");

        SecureSocketInputStream in = ss.getInputStream();
        OutputStream out = ss.getOutputStream();

        ByteBuffer incMetadataSize = ByteBuffer.allocate(4);
        in.readFully(incMetadataSize.array());

        byte[] incMetadata = new byte[incMetadataSize.getInt()];
        in.readFully(incMetadata);

        Metadata metadata = Metadata.fromBytes(incMetadata);

        int incFileSize = metadata.getFilesize();
        byte[] incFile = new byte[incFileSize];

        in.readFully(incFile);

        String filename = metadata.getFilename();
        Files.write(destDir.resolve(filename), incFile, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);

        out.write(1);
        out.flush();
    }

    @FunctionalInterface
    public interface Handler {
        void handle(SecureSocket ss) throws IOException;
    }
}
