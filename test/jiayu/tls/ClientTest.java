package jiayu.tls;

import org.junit.Test;

import java.net.InetSocketAddress;
import java.nio.file.Paths;

public class ClientTest {
    @Test
    public void connectSecured() throws Exception {
        Client client = new Client(new InetSocketAddress("localhost", 443));
        client.setCACertificate(Paths.get("misc/certs/servercert.crt"));
        client.connectSecured();
    }

}