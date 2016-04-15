package jiayu.tls;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

public class TLS_PRF_SHA256Test {
    @Test
    public void getBytes() throws Exception {
        ByteQueue byteQueue = new ByteQueue();
        ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();

        byteQueue.enqueue("hello".getBytes());
        byteOutputStream.write("hello".getBytes());

        System.out.println(Arrays.toString(byteOutputStream.toByteArray()));
        System.out.println(Arrays.toString(byteQueue.dequeue(5)));
    }

}