package jiayu.tls;

import org.junit.Test;

import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

public class SecureServerSocketTest {
    @Test
    public void testSecureServerSocket() throws Exception {
        SecureServerSocket sss = new SecureServerSocket();
        sss.setServerCert(Paths.get("misc/certs/servercert.crt"));
        sss.setServerKey(Paths.get("misc/certs/serverkey.der"));
        sss.bind(4443);
        SecureSocket ss = sss.acceptSecured();

        byte[] buf = new byte[4];
        SecureSocketInputStream in = (SecureSocketInputStream) ss.getInputStream();
        in.read(buf);

        int incDataSize = ByteBuffer.wrap(buf).getInt();
        System.out.println(incDataSize);

        buf = new byte[incDataSize];
        in.readFully(buf);
        Files.write(Paths.get("misc/files/downloaddest/newfile.txt"), buf, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
    }
}