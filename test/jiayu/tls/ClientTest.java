package jiayu.tls;

import jiayu.Client;
import org.junit.Test;

import java.nio.file.Paths;

public class ClientTest {
    @Test
    public void connectSecured() throws Exception {
        Client client = new Client();
        client.setCACertificate(Paths.get("misc/certs/servercert.crt"));
        client.connectSecured("localhost", 4443);
//        client.connectSecured("192.168.148.129", 443);
    }
}
