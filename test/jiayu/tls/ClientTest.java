package jiayu.tls;

import jiayu.Client;
import org.junit.Test;

import java.net.InetSocketAddress;
import java.nio.file.Paths;

public class ClientTest {
    @Test
    public void connectSecured() throws Exception {
        Client client = new Client(new InetSocketAddress("192.168.148.129", 443));
        client.setCACertificate(Paths.get("misc/certs/servercert.crt"));
        client.connectSecured();
    }

}
