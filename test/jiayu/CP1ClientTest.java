package jiayu;

import org.junit.Before;
import org.junit.Test;

import java.nio.file.Paths;

public class CP1ClientTest {
    private SecStoreClient cp1Client;

    @Before
    public void setUp() throws Exception {
        cp1Client = SecStoreClient.getInstance("CP1");
        cp1Client.addCACert(Paths.get("misc/certs/servercert.crt"));
        cp1Client.connect("139.59.245.167", 4443);
    }

    @Test
    public void CP1_1kB() throws Exception {
        cp1Client.uploadFile("misc/files/1kB");
    }

    @Test
    public void CP1_10kB() throws Exception {
        cp1Client.uploadFile("misc/files/10kB");
    }

    @Test
    public void CP1_100kB() throws Exception {
        cp1Client.uploadFile("misc/files/100kB");
    }

    @Test
    public void CP1_1MB() throws Exception {
        cp1Client.uploadFile("misc/files/1MB");
    }

    @Test
    public void CP1_10MB() throws Exception {
        cp1Client.uploadFile("misc/files/10MB");
    }
}