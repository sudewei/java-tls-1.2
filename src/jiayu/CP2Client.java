package jiayu;

import jiayu.tls.UInt;
import jiayu.tls.filetransfer.Metadata;

import javax.crypto.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

@SuppressWarnings("ALL")
public class CP2Client extends AbstractSecStoreClient {
    CP2Client() {

    }

    public static void main(String[] args) {
        try {
            SecStoreClient client = SecStoreClient.getInstance("CP2");
            client.addCACert(Paths.get("C:\\Users\\jiayu\\IdeaProjects\\tls-1.2-implementation-java\\misc\\certs\\servercert.crt"));
            try {
                client.connect("139.59.245.167", 443);
//                client.connect("localhost", 4443);
            } catch (IOException e) {
                System.out.println("ERROR: failed to connect to server");
            }
            boolean b = client.uploadFile("C:\\Users\\jiayu\\IdeaProjects\\tls-1.2-implementation-java\\misc\\files\\10MB");
            if (b) {
                System.out.println("Upload success!");
            } else {
                System.out.println("Upload failed.");
            }
        } catch (NoSuchAlgorithmException | IOException | CertificateException e) {
            e.printStackTrace();
        }
    }



    @Override
    public boolean uploadFile(Path file) throws IOException {
        Metadata metadata = Metadata.get(file);

        System.out.println(String.format("Uploading %s (%d bytes)", metadata.getFilename(), metadata.getFilesize()));
        byte[] fileContent = Files.readAllBytes(file);

        ByteArrayOutputStream toSend = new ByteArrayOutputStream();

        // for CP2
        toSend.write(2);

        ByteArrayOutputStream toEncrypt = new ByteArrayOutputStream();
        toEncrypt.write(metadata.getBytes());
        toEncrypt.write(fileContent);

        KeyGenerator kg = null;
        long encTime;
        try {
            kg = KeyGenerator.getInstance("AES");
            kg.init(128);
            SecretKey secretKey = kg.generateKey();
            byte[] keyBytes = secretKey.getEncoded();

            toSend.write(UInt.itob(keyBytes.length));
            toSend.write(keyBytes);

            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            System.out.println("Encrypting data...");
            long startTime = System.currentTimeMillis();
            byte[] encrypted = cipher.doFinal(toEncrypt.toByteArray());
            long endTime = System.currentTimeMillis();
            encTime = endTime - startTime;
            System.out.println("Encryption time: " + encTime + " ms");

            toSend.write(UInt.itob(encrypted.length));
            toSend.write(encrypted);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            throw new RuntimeException();
        }

        System.out.println("Sending data to server...");
        long startTime = System.currentTimeMillis();

        out.write(toSend.toByteArray());
        System.out.println("Waiting for server response...");
        boolean success = in.read() == 1;
        long endTime = System.currentTimeMillis();
        long rtt = endTime - startTime;
        System.out.println("Round trip time: " + rtt + " ms");

//        log(encTime, rtt);
        return success;
    }
}
