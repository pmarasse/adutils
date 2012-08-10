package net.archigny.adutils.password.util;

import java.util.Map;

import javax.naming.Name;

import net.archigny.adutils.password.PasswordSettings;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ldap.core.ContextMapper;
import org.springframework.ldap.core.DirContextAdapter;

public class PasswordSettingsMapper implements ContextMapper {

    private static Logger      log                             = LoggerFactory.getLogger(PasswordSettingsMapper.class);

    /**
     * Windows password Complexity flag (pwdProperties attribute)
     */
    public static int          DOMAIN_PASSWORD_COMPLEX         = 1;

    /**
     * The password cannot be changed without logging on. Otherwise, if your
     * password has expired, you can change your password and then log on.
     * (pwdProperties attribute)
     */
    public static int          DOMAIN_PASSWORD_NO_ANON_CHANGE  = 2;

    /**
     * Allows the built-in administrator account to be locked out from network
     * logons. (pwdProperties attribute)
     */
    public static int          DOMAIN_LOCKOUT_ADMINS           = 8;

    /**
     * Forces the client to use a protocol that does not allow the domain
     * controller to get the plaintext password. (pwdProperties attribute)
     */
    public static int          DOMAIN_PASSWORD_STORE_CLEARTEXT = 16;

    /**
     * Removes the requirement that the machine account password be
     * automatically changed every week. This value should not be used as it can
     * weaken security. (pwdProperties attribute)
     */
    public static int          DOMAIN_REFUSE_PASSWORD_CHANGE   = 32;

    // AD Attributes list
    public static final String AD_MAXPWDAGE                    = "maxPwdAge";
    public static final String AD_MINPWDAGE                    = "minPwdAge";
    public static final String AD_MINPWDLENGTH                 = "minPwdLength";
    public static final String AD_LOCKOUT_DURATION             = "lockoutDuration";
    public static final String AD_LOCKOUT_WINDOW               = "lockoutObservationWindow";
    public static final String AD_LOCKOUT_THRESOLD             = "lockoutThreshold";
    public static final String AD_PWD_HISTORY_LENGTH           = "pwdHistoryLength";
    public static final String AD_PWD_PROPERTIES               = "pwdProperties";

    Map<String,PasswordSettings> policies;
    
    /**
     * @param policies
     */
    public PasswordSettingsMapper(Map<String, PasswordSettings> policies) {

        super();
        this.policies = policies;
    }

    /**
     * Convert a string attribute to Long
     * 
     * @param context
     * @param attribute
     * @return
     */
    private long attributeToLong(final DirContextAdapter context, final String attribute) {

        long result;
        Object[] values = context.getObjectAttributes(attribute);
        Object value;
        if ((values != null) && ((value = values[0]) != null)) {
            result = Long.parseLong((String) value);
            return result;
        }
        // Return a value or raise an exception ?
        return 0;
    }

    private int attributeToInt(final DirContextAdapter context, final String attribute) {

        int result;
        Object[] values = context.getObjectAttributes(attribute);
        Object value;
        if ((values != null) && ((value = values[0]) != null)) {
            result = Integer.parseInt((String) value);
            return result;
        }
        // Return a value or raise an exception ?
        return 0;
    }

    @Override
    public Object mapFromContext(Object ctx) {

        DirContextAdapter context = (DirContextAdapter) ctx;

        Name dn = context.getDn();
        String name = dn.get(dn.size()-1);

        if (log.isDebugEnabled()) {
            log.debug("Context returned : Name = ["+ name + "] Attributes : " + context.getAttributes().toString());
        }
        
        long maxPwdAge;
        long minPwdAge;
        int minPwdLength;
        long lockoutDuration;
        long lockoutWindow;
        int lockoutThresold;
        int pwdHistoryLength;
        int pwdProperties;

        try {

            maxPwdAge = attributeToLong(context, AD_MAXPWDAGE);
            minPwdAge = attributeToLong(context, AD_MINPWDAGE);
            minPwdLength = attributeToInt(context, AD_MINPWDLENGTH);
            lockoutDuration = attributeToLong(context, AD_LOCKOUT_DURATION);
            lockoutWindow = attributeToLong(context, AD_LOCKOUT_WINDOW);
            lockoutThresold = attributeToInt(context, AD_LOCKOUT_THRESOLD);
            pwdHistoryLength = attributeToInt(context, AD_PWD_HISTORY_LENGTH);
            pwdProperties = attributeToInt(context, AD_PWD_PROPERTIES);

            boolean complexity = (pwdProperties & DOMAIN_PASSWORD_COMPLEX) != 0;

            policies.put(name, new PasswordSettings(false, pwdHistoryLength, complexity, minPwdLength, minPwdAge, maxPwdAge, lockoutThresold,
                    lockoutDuration, lockoutWindow));
            
        } catch (NumberFormatException e) {
            // Conversion issue, returning null...
        }
        return null;
    }

}
