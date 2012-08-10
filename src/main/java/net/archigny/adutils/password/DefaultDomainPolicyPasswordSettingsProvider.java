package net.archigny.adutils.password;

import java.util.Arrays;
import java.util.HashMap;
import net.archigny.adutils.password.util.PasswordSettingsMapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.BeanInitializationException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.LdapTemplate;

public final class DefaultDomainPolicyPasswordSettingsProvider implements IDefaultPasswordSettingsProvider, InitializingBean {

    /**
     * Logger instance
     */
    private static final Logger  log               = LoggerFactory.getLogger(DefaultDomainPolicyPasswordSettingsProvider.class);

    /**
     * Template used to query policy
     */
    private LdapTemplate         ldapTemplate;

    /**
     * Timestamp of last query
     */
    private long                 lastTimeFetched   = 0;

    /**
     * Time between two reloads of the policy
     */
    private long                 refreshInterval   = 86400000L;

    /**
     * Ldap domain DN to read (eg: dc=example, dc=com), can be empty if
     * ContextSource has a base DN
     */
    private String               domainDN          = "";

    /**
     * AD attributes read from password policies
     */
    public static final String[] attributesToFetch = { PasswordSettingsMapper.AD_MAXPWDAGE, PasswordSettingsMapper.AD_MINPWDAGE,
            PasswordSettingsMapper.AD_MINPWDLENGTH, PasswordSettingsMapper.AD_LOCKOUT_DURATION,
            PasswordSettingsMapper.AD_LOCKOUT_WINDOW, PasswordSettingsMapper.AD_LOCKOUT_THRESOLD,
            PasswordSettingsMapper.AD_PWD_HISTORY_LENGTH, PasswordSettingsMapper.AD_PWD_PROPERTIES };

    /**
     * Password settings
     */
    private PasswordSettings     ps;

    @Override
    public void afterPropertiesSet() throws Exception {

        if (ldapTemplate == null) {
            throw new BeanInitializationException("contextSource has not been set");
        }

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
     * Domain Policy fetching, should be thread-safe
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
            log.debug("Attributes fetched " + Arrays.toString(attributesToFetch));
        }

        HashMap<String, PasswordSettings> policies = new HashMap<String, PasswordSettings>();
        
        ldapTemplate.lookup(domainDN, attributesToFetch, new PasswordSettingsMapper(policies));

        if (policies.isEmpty()) {
            log.warn("No Policy has been read from LDAP !!");
            return false;
        }

        // Only override if a result has been read
        this.ps = policies.values().iterator().next();
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

}
