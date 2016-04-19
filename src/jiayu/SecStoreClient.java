package jiayu;

import java.io.IOException;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;

public interface SecStoreClient {
    static SecStoreClient getInstance(String cp) throws NoSuchAlgorithmException {
        switch (cp) {
            case "CP1":
                return new CP1Client();
            case "CP2":
                return new CP2Client();
            default:
                throw new NoSuchAlgorithmException();
        }
    }

    void connect(String host, int port) throws IOException;

    boolean uploadFile(String file) throws IOException;

    boolean uploadFile(Path file) throws IOException;

    void disconnect() throws IOException;
}
