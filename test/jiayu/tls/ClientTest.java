package jiayu.tls;

import org.junit.Test;

import java.net.InetSocketAddress;
import java.nio.file.Paths;

public class ClientTest {
    @Test
    public void connectSecured() throws Exception {
        Client client = new Client(new InetSocketAddress("192.168.198.128", 443));
        client.setCACertificate(Paths.get("C:\\Users\\jiayu\\IdeaProjects\\computer-systems-engineering\\materials\\NSProjectRelease\\keys\\server.crt"));
        client.connectSecured();
    }

}