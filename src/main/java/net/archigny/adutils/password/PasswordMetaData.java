package net.archigny.adutils.password;

/**
 * Meta data related to one password
 * 
 * @author Philippe Marasse
 */
public class PasswordMetaData {

    /**
     * Password last set in AD format (100 nanoseconds since 01/01/1601)
     */
    private long lastSet;

    /**
     * @param lastSet Password Last Set time in I8 format
     */
    public PasswordMetaData(long lastSet) {

        this.lastSet = lastSet;
    }

    public long getLastSet() {

        return lastSet;
    }

    /**
     * Convert password last set value relative to epoch (ms)
     * 
     * @return converted I8 value
     */
    public long getLastSetFromEpoch() {
        return I8.convertToEpoch(lastSet);
        
    }

    /**
     * Calculate password expiration Date in ms since epoch
     * 
     * @param pso Password Settings to apply
     * @return calculated timestamp
     */
    public long getExpirationTime(PasswordSettings pso) {
        return I8.convertToEpoch(lastSet - pso.getMaximumPasswordAge());
    }
    
}
