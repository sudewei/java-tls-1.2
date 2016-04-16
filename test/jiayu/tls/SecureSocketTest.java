package jiayu.tls;

import org.junit.Test;

import java.io.BufferedOutputStream;
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
        secureSocket.getOutputStream().write(ByteBuffer.allocate(4).putInt(largeTxt.length).array());

        BufferedOutputStream out = new BufferedOutputStream(secureSocket.getOutputStream(), 8000);
        out.write(largeTxt);

    }

    @Test
    public void getOutputStream() throws Exception {

    }

    @Test
    public void getInputStream() throws Exception {

    }

}