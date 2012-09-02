package net.archigny.adutils.password.util;

import java.util.Map;

import javax.naming.Name;

import net.archigny.adutils.password.PasswordSettings;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ldap.core.ContextMapper;
import org.springframework.ldap.core.DirContextAdapter;

public class PasswordSettingsMapper implements ContextMapper {

    private Logger                        log                             = LoggerFactory.getLogger(PasswordSettingsMapper.class);

    /**
     * Windows password Complexity flag (pwdProperties attribute)
     */
    public static int                     DOMAIN_PASSWORD_COMPLEX         = 1;

    /**
     * The password cannot be changed without logging on. Otherwise, if your password has expired, you can change your password and
     * then log on. (pwdProperties attribute)
     */
    public static int                     DOMAIN_PASSWORD_NO_ANON_CHANGE  = 2;

    /**
     * Allows the built-in administrator account to be locked out from network logons. (pwdProperties attribute)
     */
    public static int                     DOMAIN_LOCKOUT_ADMINS           = 8;

    /**
     * Forces the client to use a protocol that does not allow the domain controller to get the plaintext password. (pwdProperties
     * attribute)
     */
    public static int                     DOMAIN_PASSWORD_STORE_CLEARTEXT = 16;

    /**
     * Removes the requirement that the machine account password be automatically changed every week. This value should not be used
     * as it can weaken security. (pwdProperties attribute)
     */
    public static int                     DOMAIN_REFUSE_PASSWORD_CHANGE   = 32;

    /**
     * Default Domain Policy Attribute : Maximum Password Age in I8 format
     */
    public static final String            AD_MAXPWDAGE                    = "maxPwdAge";

    /**
     * Default Domain Policy Attribute : Minimum Password Age in I8 format
     */
    public static final String            AD_MINPWDAGE                    = "minPwdAge";

    /**
     * Default Domain Policy Attribute : Minimum password length
     */
    public static final String            AD_MINPWDLENGTH                 = "minPwdLength";

    /**
     * Default Domain Policy Attribute : Account Lockup duration in I8 format
     */
    public static final String            AD_LOCKOUT_DURATION             = "lockoutDuration";

    /**
     * Default Domain Policy Attribute : Lockout Observation Window in I8 format
     */
    public static final String            AD_LOCKOUT_WINDOW               = "lockoutObservationWindow";

    /**
     * Default Domain Policy Attribute : Account Lockout threshold
     */
    public static final String            AD_LOCKOUT_THRESHOLD            = "lockoutThreshold";

    /**
     * Default Domain Policy Attribute : Password history length
     */
    public static final String            AD_PWD_HISTORY_LENGTH           = "pwdHistoryLength";

    /**
     * Default Domain Policy Attribute : Bitmap of password properties
     */
    public static final String            AD_PWD_PROPERTIES               = "pwdProperties";

    /**
     * AD attributes read from Default Domain Policy
     */
    public static final String[]          DEFAULT_DOMAIN_POLICY_ATTRS     = { AD_MAXPWDAGE, AD_MINPWDAGE, AD_MINPWDLENGTH,
            AD_LOCKOUT_DURATION, AD_LOCKOUT_WINDOW, AD_LOCKOUT_THRESHOLD, AD_PWD_HISTORY_LENGTH, AD_PWD_PROPERTIES };

    /**
     * Password Settings Object Attribute : Maximum Password Age in I8 format
     */
    public static final String            AD_PSO_MAXPWDAGE                = "msDS-MaximumPasswordAge";

    /**
     * Password Settings Object Attribute : Minimum Password Age in I8 format
     */
    public static final String            AD_PSO_MINPWDAGE                = "msDS-MinimumPasswordAge";

    /**
     * Password Settings Object Attribute : Minimum password length
     */
    public static final String            AD_PSO_MINPWDLENGTH             = "msDS-MinimumPasswordLength";

    /**
     * Password Settings Object Attribute : Password history length
     */
    public static final String            AD_PSO_PWD_HISTORY_LENGTH       = "msDS-PasswordHistoryLength";

    /**
     * Password Settings Object Attribute : Password complexity
     */
    public static final String            AD_PSO_COMPLEXITY               = "msDS-PasswordComplexityEnabled";

    /**
     * Password Settings Object Attribute : reversible encryption
     */
    public static final String            AD_PSO_REVERSIBLE_ENC           = "msDS-PasswordReversibleEncryptionEnabled";

    /**
     * Password Settings Object Attribute : Lockout Observation Window in I8 format
     */
    public static final String            AD_PSO_LOCKOUT_WINDOW           = "msDS-LockoutObservationWindow";

    /**
     * Password Settings Object Attribute : Account Lockup duration in I8 format
     */
    public static final String            AD_PSO_LOCKOUT_DURATION         = "msDS-LockoutDuration";

    /**
     * Password Settings Object Attribute : Account Lockout threshold
     */
    public static final String            AD_PSO_LOCKOUT_THRESHOLD        = "msDS-LockoutThreshold";

    /**
     * AD attributes read from Password Settings Objects
     */
    public static final String[]          PSO_ATTRS                       = { AD_PSO_MAXPWDAGE, AD_PSO_MINPWDAGE,
            AD_PSO_MINPWDLENGTH, AD_PSO_PWD_HISTORY_LENGTH, AD_PSO_COMPLEXITY, AD_PSO_REVERSIBLE_ENC, AD_PSO_LOCKOUT_WINDOW,
            AD_PSO_LOCKOUT_DURATION, AD_PSO_LOCKOUT_THRESHOLD            };

    /**
     * String representation of boolean false returned by AD
     */
    public static final String            LDAP_TRUE_VALUE                 = "TRUE";

    /**
     * Map of the PSOs, key is PSO's suffix in lower case (cn=xxx)
     */
    private Map<String, PasswordSettings> policies;

    /**
     * Attribute set used used by ldap query (only PSO_ATTRS and DEFAULT_DOMAIN_POLICY_ATTRS are valid)
     */
    private String[]                      attributeSet;

    /**
     * @param policies
     */
    public PasswordSettingsMapper(final Map<String, PasswordSettings> policies, final String[] attributeSet) {

        if (PSO_ATTRS == attributeSet || DEFAULT_DOMAIN_POLICY_ATTRS == attributeSet) {
            this.attributeSet = attributeSet;
        } else {
            throw new IllegalArgumentException("attributeSet must be one of DEFAULT_DOMAIN_POLICY_ATTRS or PSO_ATTRS");
        }
        this.policies = policies;
    }

    /**
     * Convert a string attribute to Long
     * 
     * @param context
     * @param attribute
     * @return parsed string attribute
     */
    private long attributeToLong(final DirContextAdapter context, final String attribute) {

        Object[] values = context.getObjectAttributes(attribute);
        Object value;
        if ((values != null) && ((value = values[0]) != null)) {
            return Long.parseLong((String) value);
        }
        // Return a value or raise an exception ?
        return 0;
    }

    /**
     * Convert a string attribute to Integer
     * 
     * @param context
     * @param attribute
     * @return parsed string attribute
     */
    private int attributeToInt(final DirContextAdapter context, final String attribute) {

        Object[] values = context.getObjectAttributes(attribute);
        Object value;
        if ((values != null) && ((value = values[0]) != null)) {
            return Integer.parseInt((String) value);
        }
        // Return a value or raise an exception ?
        return 0;
    }

    /**
     * Convert a string attribute to Boolean
     * 
     * @param context
     * @param attribute
     * @return parsed string attribute
     */
    private boolean attributeToBoolean(final DirContextAdapter context, final String attribute) {

        Object[] values = context.getObjectAttributes(attribute);
        Object value;
        if ((values != null) && ((value = values[0]) != null)) {
            return LDAP_TRUE_VALUE.equalsIgnoreCase((String) value);
        }
        return false;
    }

    @Override
    public Object mapFromContext(final Object ctx) {

        final DirContextAdapter context = (DirContextAdapter) ctx;

        final Name dn = context.getDn();
        final String name = dn.get(dn.size() - 1);

        log.debug("Context returned : Name = [{}] Attributes : {}", name, context.getAttributes().toString());

        long maxPwdAge;
        long minPwdAge;
        int minPwdLength;
        long lockoutDuration;
        long lockoutWindow;
        int lockoutThresold;
        int pwdHistoryLength;
        int pwdProperties;
        boolean complexity = false;
        boolean reversible = false;

        try {

            if (attributeSet == DEFAULT_DOMAIN_POLICY_ATTRS) {
                maxPwdAge = attributeToLong(context, AD_MAXPWDAGE);
                minPwdAge = attributeToLong(context, AD_MINPWDAGE);
                minPwdLength = attributeToInt(context, AD_MINPWDLENGTH);
                lockoutDuration = attributeToLong(context, AD_LOCKOUT_DURATION);
                lockoutWindow = attributeToLong(context, AD_LOCKOUT_WINDOW);
                lockoutThresold = attributeToInt(context, AD_LOCKOUT_THRESHOLD);
                pwdHistoryLength = attributeToInt(context, AD_PWD_HISTORY_LENGTH);
                pwdProperties = attributeToInt(context, AD_PWD_PROPERTIES);

                complexity = (pwdProperties & DOMAIN_PASSWORD_COMPLEX) != 0;
            } else {
                maxPwdAge = attributeToLong(context, AD_PSO_MAXPWDAGE);
                minPwdAge = attributeToLong(context, AD_PSO_MINPWDAGE);
                minPwdLength = attributeToInt(context, AD_PSO_MINPWDLENGTH);
                lockoutDuration = attributeToLong(context, AD_PSO_LOCKOUT_DURATION);
                lockoutWindow = attributeToLong(context, AD_PSO_LOCKOUT_WINDOW);
                lockoutThresold = attributeToInt(context, AD_PSO_LOCKOUT_THRESHOLD);
                pwdHistoryLength = attributeToInt(context, AD_PSO_PWD_HISTORY_LENGTH);
                complexity = attributeToBoolean(context, AD_PSO_COMPLEXITY);
                reversible = attributeToBoolean(context, AD_PSO_REVERSIBLE_ENC);
            }

            policies.put(name.toLowerCase(), new PasswordSettings(reversible, pwdHistoryLength, complexity, minPwdLength,
                    minPwdAge, maxPwdAge, lockoutThresold, lockoutDuration, lockoutWindow));

        } catch (NumberFormatException e) {
            // Conversion issue, returning null...
        }
        return null;
    }

}
