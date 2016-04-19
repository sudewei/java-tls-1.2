package jiayu;

import org.junit.Test;

import java.nio.file.Paths;

public class CP2ClientTest {
    @Test
    public void main() throws Exception {

    }

    @Test
    public void uploadFile() throws Exception {
        new CP2Client().uploadFile(Paths.get(""));
    }

}