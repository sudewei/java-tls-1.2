package jiayu.tls;

import org.junit.Test;

import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;

public class SecureSocketTest {
    @Test
    public void connectSecured() throws Exception {
        SecureSocket secureSocket = new SecureSocket();
        secureSocket.setCACertificate(Paths.get("misc/certs/servercert.crt"));
        secureSocket.connectSecured("localhost", 4443);

        byte[] largeTxt = Files.readAllBytes(Paths.get("misc/files/largeSize.txt"));
        OutputStream out = secureSocket.getOutputStream();
        out.write(ByteBuffer.allocate(4).putInt(largeTxt.length).array());
        out.write(largeTxt);
        out.flush();
    }
}