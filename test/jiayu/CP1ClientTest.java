package jiayu;

import org.junit.Test;

public class CP1ClientTest {
    @Test
    public void uploadFile() throws Exception {
        SecStoreClient client = SecStoreClient.getInstance("CP1");
        client.connect("localhost", 4443);
        if (client.uploadFile("misc/files/10MB")) {
            System.out.println("Upload success!");
        } else {
            System.out.println("Upload failed.");
        }

    }

}