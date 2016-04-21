package jiayu;

import org.junit.Before;
import org.junit.Test;

import java.nio.file.Paths;

public class CP2ClientTest {
    private SecStoreClient cp2Client;

    @Before
    public void setUp() throws Exception {
        cp2Client = SecStoreClient.getInstance("CP2");
        cp2Client.addCACert(Paths.get("misc/certs/servercert.crt"));
        cp2Client.connect("139.59.245.167", 4443);
    }

    @Test
    public void CP2_1kB() throws Exception {
        cp2Client.uploadFile("misc/files/1kB");
    }

    @Test
    public void CP2_10kB() throws Exception {
        cp2Client.uploadFile("misc/files/10kB");
    }

    @Test
    public void CP2_100kB() throws Exception {
        cp2Client.uploadFile("misc/files/100kB");
    }

    @Test
    public void CP2_1MB() throws Exception {
        cp2Client.uploadFile("misc/files/1MB");
    }

    @Test
    public void CP2_10MB() throws Exception {
        cp2Client.uploadFile("misc/files/10MB");
    }
}