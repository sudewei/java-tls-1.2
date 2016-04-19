package jiayu;

import jiayu.tls.SecureSocket;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateException;

public abstract class AbstractSecStoreClient implements SecStoreClient {

    static final Path CA_CERT = Paths.get("C:\\Users\\jiayu\\IdeaProjects\\tls-1.2-implementation-java\\misc\\certs\\servercert.crt");

    boolean connected;

    SecureSocket socket;
    InputStream in;
    OutputStream out;

    AbstractSecStoreClient() {
        connected = false;
    }

    @Override
    public void connect(String host, int port) throws IOException {
        try {
            socket = new SecureSocket(host, port, CA_CERT);
            in = socket.getInputStream();
            out = socket.getOutputStream();
            connected = true;
        } catch (CertificateException e) {
            e.printStackTrace();
            throw new RuntimeException();
        }
    }

    @Override
    public boolean uploadFile(String file) throws IOException {
        return uploadFile(Paths.get(file));
    }

    @Override
    public void disconnect() throws IOException {
        if (!connected) throw new IllegalStateException("not connected");

        in.close();
        out.close();

        socket.close();
    }
}
