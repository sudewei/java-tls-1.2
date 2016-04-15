package jiayu.tls;

public enum MACAlgorithm {
    NULL("NULL", 0, 0),
    HMAC_SHA256("HmacSHA256", 32, 32);

    public final String name;
    public final int macLength;
    public final int macKeyLength;

    MACAlgorithm(String name, int macLength, int macKeyLength) {
        this.name = name;
        this.macLength = macLength;
        this.macKeyLength = macKeyLength;
    }

    @Override
    public String toString() {
        return name;
    }
}
