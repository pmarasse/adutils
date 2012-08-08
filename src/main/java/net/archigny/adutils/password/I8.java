package net.archigny.adutils.password;

/**
 * Class of constants used widely in password related calculations
 * 
 * @author Philippe Marasse
 */
public final class I8 {

    /**
     * Constant AD value for "never" (can be used as maximumPasswordAge value)
     */
    public static final long NEVER  = -9223372036854775808L;

    /**
     * Constant I8 value for 1 second
     */
    public static final long SECOND = -10000000L;

    /**
     * Constant I8 value for 1 minute
     */
    public static final long MINUTE = -600000000L;

    /**
     * Constant I8 value for 1 hour
     */
    public static final long HOUR   = -36000000000L;

    /**
     * Constant I8 value for 1 day
     */
    public static final long DAY    = -864000000000L;

    /**
     * Days between 1601 (base of AD dates) and epoch : 369 years * 365 days + 92 leap years - 3 non-leap centuries
     */
    public static final long DAYS_1601_TO_1970 = 134774L;

    /**
     * Positive value of delta between epoch and AD base (0.1µs)
     */
    public static final long AD_TO_EPOCH = - DAYS_1601_TO_1970 * DAY;
    
    /**
     * Scale factor between AD (0.1µs) and Java Data/Time (ms)
     */
    public static final long AD_TO_TIME_SCALE = 10000L;
    
    /**
     * Convert I8 date value to miliseconds since Epoch
     * 
     * @param adTimestamp value to convert
     * @return result of the conversion
     */
    public static final long convertToEpoch(long adTimestamp) {
        return (adTimestamp - AD_TO_EPOCH) / AD_TO_TIME_SCALE;
    }
    
    /**
     * Convert a timestamp (miliseconds since Epoch) to I8 value
     * 
     * @param timestamp value to convert
     * @return result of the conversion
     */
    public static final long convertToI8(long timestamp) {
        return timestamp * AD_TO_TIME_SCALE + AD_TO_EPOCH; 
    }
    
}
