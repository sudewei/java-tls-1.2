package jiayu;

import jiayu.tls.SecureServerSocket;
import jiayu.tls.SecureSocket;
import jiayu.tls.SecureSocketInputStream;
import jiayu.tls.filetransfer.Metadata;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SecStore {
    private static final int CP1 = 1;
    private static final int CP2 = 2;

    private final ExecutorService executorService;

    private Path destDir;
    private SecureServerSocket sss;

    private boolean listening;
    private boolean interactive;

    public SecStore() throws IOException {
        int numCores = Runtime.getRuntime().availableProcessors();
        System.out.println("Number of available cores: " + numCores);
        System.out.println(String.format("Using %d threads.", numCores));
        executorService = Executors.newFixedThreadPool(numCores);

        sss = new SecureServerSocket();
        listening = false;
    }

    public void setServerCert(Path serverCert) throws IOException {
        sss.setServerCert(serverCert);
    }

    public void setServerKey(Path serverKey) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
        sss.setServerKey(serverKey);
    }

    public void setDestDir(Path path) {
        destDir = path;
    }

    public void bind(int port) throws IOException {
        sss.bind(port);
    }

    public void listen() throws IOException {
        listening = true;
        while (listening) {

            SecureSocket ss = sss.acceptSecured();
            executorService.execute(() -> {
                System.out.println(Thread.currentThread().getName() + " handling a request from " + ss.getSocket().getInetAddress().getHostAddress());
                receiveFile(ss);
            });
        }
    }

//    public void listen(Handler handler) throws IOException {
//        listening = true;
//        while (listening) {
//
//            SecureSocket ss = sss.acceptSecured();
//            executorService.execute(() -> receiveFile(ss));
//        }
//    }

    public void receiveBytes(byte[] bytes) {

    }

    public void receiveFile(SecureSocket ss) {
        if (destDir == null) throw new IllegalStateException("no destination directory set");

        SecureSocketInputStream in = ss.getInputStream();
        OutputStream out = ss.getOutputStream();

        ByteBuffer buf = ByteBuffer.allocate(1 + Integer.BYTES);
        try {
            in.readFully(buf.array());
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException();
        }

        int protocol = buf.get();
        int keyLength = buf.getInt();

        byte[] keyBytes = new byte[keyLength];
        try {
            in.readFully(keyBytes);
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException();
        }

        buf = ByteBuffer.allocate(Integer.BYTES);
        try {
            in.readFully(buf.array());
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException();
        }
        int dataLength = buf.getInt();

        ByteArrayOutputStream plaintext = new ByteArrayOutputStream();
        byte[] content;

        // decrypt differently based on protocol
        switch (protocol) {
            case CP1:
                content = decryptCP1(in, keyBytes, dataLength);
                break;
            case CP2:
                content = decryptCP2(in, keyBytes, dataLength);
                break;
            default:
                throw new IllegalStateException();
        }

        buf = ByteBuffer.wrap(content);

        int metadataLength = buf.getInt();
        byte[] metadataBytes = new byte[metadataLength];
        buf.get(metadataBytes);

        Metadata metadata = Metadata.fromBytes(metadataBytes);
        System.out.println(String.format("Receiving file %s (%d bytes)", metadata.getFilename(), metadata.getFilesize()));

        byte[] fileBytes = new byte[metadata.getFilesize()];
        assert buf.remaining() == fileBytes.length;
        buf.get(fileBytes);

        System.out.println("Received SHA-256 checksum:   " + DatatypeConverter.printBase64Binary(metadata.getChecksum()));

        byte[] checksumVerify = Metadata.calculateChecksum(fileBytes);
        System.out.println("Calculated SHA-256 checksum: " + DatatypeConverter.printBase64Binary(checksumVerify));

        if (!Arrays.equals(metadata.getChecksum(), checksumVerify)) {
            throw new RuntimeException();
        } else System.out.println("File verified.");


        String filename = metadata.getFilename();

        try {
            Files.write(destDir.resolve(filename), fileBytes, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
        } catch (IOException e) {
            try {
                out.write(0);
            } catch (IOException e1) {
                throw new RuntimeException();
            }
        }

        try {
            out.write(1);
            out.flush();
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException();
        }
    }

    private byte[] decryptCP2(SecureSocketInputStream in, byte[] keyBytes, int dataLength) {
        byte[] content;

        byte[] toDecrypt = new byte[dataLength];
        try {
            in.readFully(toDecrypt);
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException();
        }

        SecretKeySpec sks = new SecretKeySpec(keyBytes, "AES");
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, sks);
            content = cipher.doFinal(toDecrypt);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | InvalidKeyException | BadPaddingException e) {
            e.printStackTrace();
            throw new RuntimeException();
        }
        return content;
    }

    private static byte[] decryptCP1(SecureSocketInputStream in, byte[] keyBytes, int dataLength) {
        ArrayList<byte[]> ciphertext = new ArrayList<>();
        int bytesRead = 0;
        while (bytesRead < dataLength) {
            byte[] block = new byte[128];
            try {
                in.readFully(block);
            } catch (IOException e) {
                e.printStackTrace();
                throw new RuntimeException();
            }
            bytesRead += 128;
            ciphertext.add(block);
        }

        ArrayList<byte[]> plaintext = new ArrayList<>();

        Cipher cipher;
        try {
            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keyBytes));
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidKeySpecException e) {
            e.printStackTrace();
            throw new RuntimeException();
        }

        long startTime = System.currentTimeMillis();
        for (byte[] bytes : ciphertext) {
            try {
                plaintext.add(cipher.doFinal(bytes));
            } catch (IllegalBlockSizeException | BadPaddingException e) {
                e.printStackTrace();
                throw new RuntimeException();
            }
        }
        long endTime = System.currentTimeMillis();
        System.out.println("Decryption time: " + (endTime - startTime));

        // reassemble content
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] bytes : plaintext)
            try {
                out.write(bytes);
            } catch (IOException e) {
                e.printStackTrace();
                throw new RuntimeException();
            }
        return out.toByteArray();
    }

    @FunctionalInterface
    public interface Handler {
        void handle(SecureSocket ss);
    }

    private void startInteractiveMode() {
        Scanner scanner = new Scanner(System.in);
        interactive = true;
        while (interactive) {
            System.out.print("SecStore > ");
            String input = scanner.nextLine();
            parse(input);
        }
    }

    private void parse(String input) {
        String[] tokens = input.split(" ");

        String command = tokens[0];
        String[] args = Arrays.copyOfRange(tokens, 1, tokens.length);

        execute(command, args);
    }

    private void execute(String command, String... args) {
        switch (command) {
            case "pwd":
                Path current = Paths.get("");
                System.out.println(current.toAbsolutePath().toString());
                break;
            case "cd":
                cd(args);
                break;
            case "set":
                set(args);
                break;
            case "bind":
                int port;
                try {
                    if (args.length < 1) {
                        System.out.println("invalid arguments!");
                        return;
                    }
                    port = Integer.parseInt(args[0]);
                    bind(port);
                    System.out.println("Successfully bound to port " + port);
                } catch (NumberFormatException e) {
                    System.out.println("Invalid port number!");
                } catch (IOException e) {
                    System.out.println("ERROR");
                    e.printStackTrace();
                }
                break;
            case "newsocket":
                if (sss != null) {
                    System.out.println("SecStore already has an underlying socket.");
                }
                sss = new SecureServerSocket();
                System.out.println("Socket initialised.");
                break;
            case "listen":
                try {
                    System.out.println("Server listening...");
                    listen();
                } catch (IOException e) {
                    System.out.println("ERROR");
                    e.printStackTrace();
                }
                break;
            case "quickstart":
                if (args.length < 1) {
                    System.out.println("ERROR: invalid config file");
                    return;
                }
                startFromConfigFile(Paths.get(args[0]));

                break;
            case "stop":
                try {
                    System.out.println("Closing underlying socket... (You may see some error messages.)");
                    sss.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                break;
            case "exit":
                interactive = false;
                System.out.println("Exiting SecStore.");
                break;
            default:
                System.out.println("Invalid command!");

        }
    }

    private void set(String... args) {
        switch (args[0]) {
            case "servercert":
                try {
                    if (args.length < 2) {
                        System.out.println("invalid arguments!");
                        return;
                    }
                    setServerCert(Paths.get(args[1]));
                    System.out.println("New server cert set.");
                } catch (IOException e) {
                    System.out.println("ERROR");
                    e.printStackTrace();
                }
                break;
            case "serverkey":
                try {
                    if (args.length < 2) {
                        System.out.println("invalid arguments!");
                        return;
                    }

                    setServerKey(Paths.get(args[1]));
                    System.out.println("New server key set.");
                } catch (InvalidKeySpecException | NoSuchAlgorithmException | IOException e) {
                    System.out.println("ERROR");
                    e.printStackTrace();
                }
                break;
            case "destdir":
                if (args.length < 2) {
                    System.out.println("invalid arguments!");
                    return;
                }
                setDestDir(Paths.get(args[1]));
                System.out.println("New destination directory set.");
                break;
            default:
                System.out.println("Invalid command!");
        }
    }

    public static void main(String[] args) {
        try {
            SecStore store = new SecStore();
            System.out.println("Starting SecStore interactive mode");
            store.startInteractiveMode();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void startFromConfigFile(Path configFile) {
        if (!Files.exists(configFile)) throw new IllegalStateException();

        try {
            List<String> config = Files.readAllLines(configFile);
            if (config.size() < 3) throw new IOException();
            if (sss == null) sss = new SecureServerSocket();
            setServerCert(Paths.get(config.get(0)));
            setServerKey(Paths.get(config.get(1)));
            setDestDir(Paths.get(config.get(2)));
            bind(Integer.parseInt(config.get(3)));
            System.out.println("Listening...");
            listen();

        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | NumberFormatException e) {
            System.out.println("Invalid config file!");
            e.printStackTrace();
        }
    }

    private void cd(String... args) {
        if (args.length < 1) {
            execute("pwd");
        } else {
            String cmd = "cd " + args[0];
            String[] bash = { "/bin/sh", "-c", cmd };

            try {
                Process p = Runtime.getRuntime().exec(bash);
            } catch (IOException e) {
                e.printStackTrace();
                System.out.println("Encountered an unknown error.");
            }

        }
    }
}
