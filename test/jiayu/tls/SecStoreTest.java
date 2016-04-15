package jiayu.tls;

import jiayu.SecStore;
import org.junit.Test;

import java.nio.file.Paths;

public class SecStoreTest {
    @Test
    public void receiveConnectionSecured() throws Exception {
//        SecStore secStore = new SecStore(4443);
        SecStore secStore = new SecStore(443);
        secStore.setServerCert(Paths.get("misc/certs/servercert.crt"));
        secStore.setServerKey(Paths.get("misc/certs/serverkey.der"));
        secStore.listen(secStore::receiveConnectionSecured);
    }
}
