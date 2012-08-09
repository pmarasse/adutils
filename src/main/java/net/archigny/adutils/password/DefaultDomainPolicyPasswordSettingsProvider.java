package net.archigny.adutils.password;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.ldap.core.ContextMapper;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.LdapTemplate;

public final class DefaultDomainPolicyPasswordSettingsProvider implements IDefaultPasswordSettingsProvider, InitializingBean {

    /**
     * Windows password Complexity flag (pwdProperties attribute)
     */
    public static int            DOMAIN_PASSWORD_COMPLEX         = 1;

    /**
     * The password cannot be changed without logging on. Otherwise, if your password has expired, you can change your password and
     * then log on. (pwdProperties attribute)
     */
    public static int            DOMAIN_PASSWORD_NO_ANON_CHANGE  = 2;

    /**
     * Allows the built-in administrator account to be locked out from network logons. (pwdProperties attribute)
     */
    public static int            DOMAIN_LOCKOUT_ADMINS           = 8;

    /**
     * Forces the client to use a protocol that does not allow the domain controller to get the plaintext password. (pwdProperties
     * attribute)
     */
    public static int            DOMAIN_PASSWORD_STORE_CLEARTEXT = 16;

    /**
     * Removes the requirement that the machine account password be automatically changed every week. This value should not be used
     * as it can weaken security. (pwdProperties attribute)
     */
    public static int            DOMAIN_REFUSE_PASSWORD_CHANGE   = 32;

    /**
     * Logger instance
     */
    private static final Logger  log                             = LoggerFactory
                                                                         .getLogger(DefaultDomainPolicyPasswordSettingsProvider.class);

    /**
     * Template used to query policy
     */
    private LdapTemplate         ldapTemplate;

    /**
     * Timestamp of last query
     */
    private long                 lastTimeFetched                 = 0;

    /**
     * Time between two reloads of the policy
     */
    private long                 refreshInterval                 = 86400000L;

    /**
     * Ldap domain DN to read (eg: dc=example, dc=com), can be empty if ContextSource has a base DN
     */
    private String               domainDN                        = "";

    // AD Attributes list
    public static final String   AD_MAXPWDAGE                    = "maxPwdAge";
    public static final String   AD_MINPWDAGE                    = "minPwdAge";
    public static final String   AD_MINPWDLENGTH                 = "minPwdLength";
    public static final String   AD_LOCKOUT_DURATION             = "lockoutDuration";
    public static final String   AD_LOCKOUT_WINDOW               = "lockoutObservationWindow";
    public static final String   AD_LOCKOUT_THRESOLD             = "lockouThresold";
    public static final String   AD_PWD_HISTORY_LENGTH           = "pwdHistoryLength";
    public static final String   AD_PWD_PROPERTIES               = "pwdProperties";

    /**
     * AD attributes read from password policies
     */
    public static final String[] attributesToFetch               = { AD_MAXPWDAGE, AD_MINPWDAGE, AD_MINPWDLENGTH,
            AD_LOCKOUT_DURATION, AD_LOCKOUT_WINDOW, AD_LOCKOUT_THRESOLD, AD_PWD_HISTORY_LENGTH, AD_PWD_PROPERTIES };

    /**
     * Password settings
     */
    private PasswordSettings     ps;

    @Override
    public void afterPropertiesSet() throws Exception {

        if (!updatePasswordSettings(true) && log.isInfoEnabled()) {
            log.info("PasswordPolicy has not been read although forceUpdate = true. Another reload attempt will be done at first query");
        }
    }

    @Override
    public PasswordSettings getPasswordSettings() {

        updatePasswordSettings(false);
        return ps;
    }

    /**
     * Domain Policy fetching should be thread-safe
     * 
     * @return true if fetch has really been done
     */
    private synchronized boolean updatePasswordSettings(boolean forceUpdate) {

        if ((System.currentTimeMillis() <= lastTimeFetched + refreshInterval) && !forceUpdate && (ps != null)) {
            return false;
        }

        if (log.isDebugEnabled()) {
            log.debug("Password policy will be read : " + ((ps == null) ? " it has never been fetched." : "")
                    + ((forceUpdate) ? " Update has been forced." : ""));
        }

        PasswordSettings result = (PasswordSettings) ldapTemplate
                .lookup(domainDN, attributesToFetch, new PasswordSettingsFetcher());

        if (result == null) {
            log.warn("No Policy has been read from LDAP !!");
            return false;
        }

        // Only override if a result has been read
        this.ps = result;
        this.lastTimeFetched = System.currentTimeMillis();

        return true;
    }

    // Setters & Getters

    public void setContextSource(ContextSource cs) {

        this.ldapTemplate = new LdapTemplate(cs);
    }

    public void setDomainDN(String domainDN) {

        if (domainDN != null) {
            this.domainDN = domainDN;
        }
    }

    public String getBaseDN() {

        return domainDN;
    }

    private class PasswordSettingsFetcher implements ContextMapper {

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
            if (log.isDebugEnabled()) {
                log.debug("Attributes returned by context : " + context.getAttributes().toString());
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

                return new PasswordSettings(false, pwdHistoryLength, complexity, minPwdLength, minPwdAge, maxPwdAge,
                        lockoutThresold, lockoutDuration, lockoutWindow);

            } catch (NumberFormatException e) {
                // Conversion issue, returning null...
            }
            return null;
        }

    }
}
