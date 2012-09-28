package net.archigny.adutils.password;

/**
 * POJO representing a Password Settings Object (PSO) for fine grained passwords of Active Directory (since AD2008)
 * 
 * voir : http://technet.microsoft.com/en-us/library/cc770842%28v=ws.10%29
 * 
 * @author Philippe Marasse <philippe.marasse@laposte.net>
 * 
 */
public final class PasswordSettings {

    /**
     * True if password will be stored with a reversible encryption mechanism
     */
    private boolean reversibleEncryption;

    /**
     * 0 : no password history 1-1024 : length of password history to be kept by AD
     */
    private int     historyLength;

    /**
     * True if password complexity is enabled
     */
    private boolean passwordComplexity;

    /**
     * Minimum password lenght in characters
     */
    private int     minimumPasswordLength;

    /**
     * Minimum password age in I8 format
     */
    private long    minimumPasswordAge;

    /**
     * Maximum password age in I8 format
     */
    private long    maximumPasswordAge;

    /**
     * Maximum password tries before locking an account in I8 format
     */
    private int     lockoutThreshold;

    /**
     * Lockout duration for locked out user accounts in I8 format
     */
    private long    lockoutDuration;

    /**
     * Observation Window for lockout of user accounts in I8 format
     */
    private long    lockoutObservationWindow;

    /**
     * Are attributes satisfying referential integrity
     */
    private boolean valid = false;

    /**
     * Validate attributes referential integrity voir : http://technet.microsoft.com/en-us/library/cc753858%28v=ws.10%29.aspx
     */
    private synchronized boolean validate() {

        boolean valid = true;
        // Beware : long values are stored in I8 format !!

        // maximum password age cannot be zero
        if (maximumPasswordAge == 0) {
            valid = false;
        } else
        // password ages : minimum <= maximum.
        if (minimumPasswordAge < maximumPasswordAge) {
            valid = false;
        } else
        // lochoutObservationWindow <= lockoutDuration
        if (lockoutDuration > lockoutObservationWindow) {
            valid = false;
        }

        this.valid = valid;
        return valid;
    }

    /**
     * Creates an instance with all parameters.
     */
    public PasswordSettings(final boolean reversibleEncryption, final int historyLength, final boolean passwordComplexity,
            final int minimumPasswordLength, final long minimumPasswordAge, final long maximumPasswordAge,
            final int lockoutThreshold, final long lockoutDuration, final long lockoutObservationWindow) {

        this.reversibleEncryption = reversibleEncryption;
        this.historyLength = historyLength;
        this.passwordComplexity = passwordComplexity;
        this.minimumPasswordLength = minimumPasswordLength;
        this.minimumPasswordAge = minimumPasswordAge;
        this.maximumPasswordAge = maximumPasswordAge;
        this.lockoutThreshold = lockoutThreshold;
        this.lockoutDuration = lockoutDuration;
        this.lockoutObservationWindow = lockoutObservationWindow;
        validate();
    }

    // Setters & Getters

    public boolean isReversibleEncryption() {

        return reversibleEncryption;
    }

    public void setReversibleEncryption(final boolean reversibleEncryption) {

        this.reversibleEncryption = reversibleEncryption;
    }

    public int getHistoryLength() {

        return historyLength;
    }

    public void setHistoryLength(final int historyLength) {

        this.historyLength = historyLength;
    }

    public boolean isPasswordComplexity() {

        return passwordComplexity;
    }

    public void setPasswordComplexity(final boolean passwordComplexity) {

        this.passwordComplexity = passwordComplexity;
    }

    public int getMinimumPasswordLength() {

        return minimumPasswordLength;
    }

    public void setMinimumPasswordLength(final int minimumPasswordLength) {

        this.minimumPasswordLength = minimumPasswordLength;
    }

    public long getMinimumPasswordAge() {

        return minimumPasswordAge;
    }

    public void setMinimumPasswordAge(final long minimumPasswordAge) {

        this.minimumPasswordAge = minimumPasswordAge;
        validate();
    }

    public long getMaximumPasswordAge() {

        return maximumPasswordAge;
    }

    public void setMaximumPasswordAge(final long maximumPasswordAge) {

        this.maximumPasswordAge = maximumPasswordAge;
        validate();
    }

    public int getLockoutThreshold() {

        return lockoutThreshold;
    }

    public void setLockoutThreshold(final int lockoutThreshold) {

        this.lockoutThreshold = lockoutThreshold;
    }

    public long getLockoutDuration() {

        return lockoutDuration;
    }

    public void setLockoutDuration(final long lockoutDuration) {

        this.lockoutDuration = lockoutDuration;
        validate();
    }

    public long getLockoutObservationWindow() {

        return lockoutObservationWindow;
    }

    public void setLockoutObservationWindow(final long lockoutObservationWindow) {

        this.lockoutObservationWindow = lockoutObservationWindow;
        validate();
    }

    public boolean isValid() {

        return valid;
    }

}
