package jiayu;

import jiayu.tls.UInt;
import jiayu.tls.filetransfer.Metadata;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicInteger;

@SuppressWarnings("ALL")
public class CP1Client extends AbstractSecStoreClient {
    public static void main(String[] args) {
        try {
            SecStoreClient client = SecStoreClient.getInstance("CP1");
            client.addCACert(Paths.get("C:\\Users\\jiayu\\IdeaProjects\\tls-1.2-implementation-java\\misc\\certs\\servercert.crt"));
            client.connect("localhost", 4443);
            boolean b = client.uploadFile("C:\\Users\\jiayu\\IdeaProjects\\tls-1.2-implementation-java\\misc\\files\\1MB");
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
        // prepare the data by RSA encrypting it in 117 byte chunks
        Metadata metadata = Metadata.get(file);
        byte[] plaintext = Files.readAllBytes(file);

        ByteArrayOutputStream toEncrypt = new ByteArrayOutputStream();
        toEncrypt.write(metadata.getBytes());
        toEncrypt.write(plaintext);

        ByteBuffer buf = ByteBuffer.wrap(toEncrypt.toByteArray());

        ArrayList<byte[]> plaintextBlocks = new ArrayList<>();
        while (buf.remaining() > 117) {
            byte[] temp = new byte[117];
            buf.get(temp);
            plaintextBlocks.add(temp);
        }
        byte[] temp = new byte[buf.remaining()];
        buf.get(temp);
        plaintextBlocks.add(temp);

        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new IOException();
        }
        kpg.initialize(1024);
        KeyPair kp = kpg.generateKeyPair();

        Key publicKey = kp.getPublic();
        Key privateKey = kp.getPrivate();

        Object[] plaintextBlocksArray = plaintextBlocks.toArray();
        byte[][] ciphertextBlocksArray = new byte[plaintextBlocksArray.length][];

        System.out.println("Encrypting data...");
        System.out.printf("  0%% |                                        |");
        long startTime = System.currentTimeMillis();

        // parallel
        encryptParallel(privateKey, plaintextBlocksArray, ciphertextBlocksArray, 4);

        // sequential
//        encryptSequential(privateKey, plaintextBlocksArray, ciphertextBlocksArray);

        long endTime = System.currentTimeMillis();

        System.out.println();
        System.out.println("Encryption time: " + (endTime - startTime));

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] pubKeyBytes = publicKey.getEncoded();

        output.write(1);
        output.write(UInt.itob(pubKeyBytes.length));
        output.write(pubKeyBytes);

        int dataLength = 0;
        for (byte[] bytes : ciphertextBlocksArray) dataLength += bytes.length;

        output.write(UInt.itob(dataLength));

        for (byte[] bytes : ciphertextBlocksArray) output.write(bytes);

        System.out.println("Sending data to server...");
        out.write(output.toByteArray());
        System.out.println("Waiting for server response");
        return in.read() == 1;
    }

    private void encryptSequential(Key privateKey, Object[] src, byte[][] dst) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            for (int i = 0; i < src.length; i++) {
                dst[i] = cipher.doFinal((byte[]) src[i]);
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            throw new RuntimeException();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
            throw new RuntimeException();
        } catch (BadPaddingException e) {
            e.printStackTrace();
            throw new RuntimeException();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            throw new RuntimeException();
        }
    }

    private void encryptParallel(Key privateKey, Object[] src, byte[][] dst, int numThreads) {
        final int numBlocks = src.length;
        final int step = numBlocks / 100;
        final AtomicInteger counter = new AtomicInteger(0);
        final AtomicInteger runningCount = new AtomicInteger(0);

        Thread[] threads = new Thread[numThreads];
        for (int i = 0; i < numThreads; i++) {
            threads[i] = new Thread(new EncryptionWorker(privateKey, src, dst, numThreads, i, counter, runningCount));
            threads[i].start();
        }
        for (Thread thread : threads) {
            try {
                thread.join();
            } catch (InterruptedException e) {
                e.printStackTrace();
                throw new RuntimeException();
            }
        }
    }

    private class EncryptionWorker implements Runnable {
        final Key privateKey;
        final Object[] src;
        final byte[][] dst;
        final int numThreads;
        final int index;
        final AtomicInteger counter;
        final AtomicInteger runningCount;

        final int step;
        final Cipher cipher;

        EncryptionWorker(Key privateKey, Object[] src, byte[][] dst, int numThreads, int index,
                         AtomicInteger counter, AtomicInteger runningCount) {
            this.privateKey = privateKey;
            this.src = src;
            this.dst = dst;
            this.numThreads = numThreads;
            this.index = index;
            this.counter = counter;
            this.runningCount = runningCount;

            step = src.length / 20;

            try {
                this.cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                e.printStackTrace();
                throw new RuntimeException();
            }
        }

        @Override
        public void run() {
            for (int i = 0; ; i++) {
                int current = i * numThreads + index;
                try {
                    cipher.init(Cipher.ENCRYPT_MODE, privateKey);
                    dst[current] = cipher.doFinal((byte[]) src[current]);
                    counter.getAndIncrement();
                    if (counter.compareAndSet(step, 0)) {
                        int progress = runningCount.incrementAndGet();
                        System.out.printf("\r%3d%% |%s%s|", progress * 5, new String(new char[progress]).replace("\0", "=="), new String(new char[20 - progress]).replace("\0", "  "));
                    }
                } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
                    e.printStackTrace();
                    throw new RuntimeException();
                }
                if (current + numThreads >= src.length) break;
            }
        }
    }

}
