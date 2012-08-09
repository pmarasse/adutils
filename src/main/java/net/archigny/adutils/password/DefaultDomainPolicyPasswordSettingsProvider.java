package net.archigny.adutils.password;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.ldap.core.ContextMapper;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.LdapTemplate;

public final class DefaultDomainPolicyPasswordSettingsProvider implements IDefaultPasswordSettingsProvider, InitializingBean {

    private final Logger         log               = LoggerFactory.getLogger(DefaultDomainPolicyPasswordSettingsProvider.class);

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
    public static final String[] attributesToFetch = { "maxPwdAge", "minPwdAge", "minPwdLength" };

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
            log.debug("Password policy will be read : " + 
                    ((ps == null) ? " it has never been fetched." : "") + 
                    ((forceUpdate) ? " Update has been forced." : ""));
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

        @Override
        public Object mapFromContext(Object ctx) {

            DirContextAdapter context = (DirContextAdapter) ctx;
            if (log.isDebugEnabled()) {
                log.debug("Attributes returned by context : " + context.getAttributes().toString());
            }

            // TODO Auto-generated method stub
            return null;
        }

    }
}
