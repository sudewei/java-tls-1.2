package jiayu;

import java.io.IOException;
import java.nio.file.Path;

public class CP2Client extends AbstractSecStoreClient {

    @Override
    public void connect(String host, int port) throws IOException {

    }

    @Override
    public boolean uploadFile(Path file) throws IOException {
        return false;
    }

    @Override
    public void disconnect() throws IOException {

    }
}
