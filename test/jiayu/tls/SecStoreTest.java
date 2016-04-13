package jiayu.tls;

import org.junit.Test;

import java.net.InetSocketAddress;
import java.nio.file.Paths;

public class SecStoreTest {
    @Test
    public void receiveConnectionSecured() throws Exception {
        SecStore secStore = new SecStore(new InetSocketAddress("192.168.148.129", 443));
        secStore.setServerCert(Paths.get("misc/certs/servercert.crt"));
        secStore.setServerKey(Paths.get("misc/certs/serverkey.der"));
        secStore.listen(secStore::receiveConnectionSecured);
    }

}