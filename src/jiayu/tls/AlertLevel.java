package jiayu.tls;

public enum AlertLevel {
    WARNING(1), FATAL(2);

    public final byte value;

    AlertLevel(int value) {
        if (value < 1 && value > 2) throw new IllegalArgumentException();
        this.value = (byte) value;
    }

    public static AlertLevel valueOf(byte value) throws FatalAlertException {
        if (value == 1) return WARNING;
        else if (value == 2) return FATAL;
        else throw new FatalAlertException(AlertDescription.DECODE_ERROR);
    }
}
