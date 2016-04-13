package jiayu.tls;

import org.junit.Test;

import java.net.InetSocketAddress;
import java.nio.file.Paths;

public class SecStoreTest {
    @Test
    public void receiveConnectionSecured() throws Exception {
        SecStore secStore = new SecStore(new InetSocketAddress("localhost", 4321));
        secStore.setServerCert(Paths.get("C:\\Users\\jiayu\\IdeaProjects\\computer-systems-engineering\\materials\\NSProjectRelease\\keys\\server.crt"));
        secStore.setServerKey(Paths.get("C:\\Users\\jiayu\\IdeaProjects\\computer-systems-engineering\\materials\\NSProjectRelease\\keys\\pkcs8ServerKey.der"));
        secStore.listen(secStore::receiveConnectionSecured);
    }

}