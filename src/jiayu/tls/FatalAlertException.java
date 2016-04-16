package jiayu.tls;

public class FatalAlertException extends TLSException {
    private final AlertDescription desc;
    public FatalAlertException(AlertDescription desc) {
        super(desc.name());
        this.desc = desc;
    }

    public AlertDescription getAlertDescription() {
        return desc;
    }
}
