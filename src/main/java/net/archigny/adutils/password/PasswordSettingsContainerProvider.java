package net.archigny.adutils.password;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.naming.Name;
import javax.naming.directory.SearchControls;

import net.archigny.adutils.password.util.PasswordSettingsMapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.BeanInitializationException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.ldap.BadLdapGrammarException;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.ldap.core.LdapTemplate;

/**
 * Password Settings provider that reads content of the AD Container (since AD2008), usual DN is : <br />
 * CN=Password Settings Container, CN=System, DC=example, DC=com
 * 
 * @author Philippe MARASSE
 * 
 */
public final class PasswordSettingsContainerProvider implements InitializingBean, IPasswordSettingsProvider {

    /**
     * Logger instance
     */
    private final Logger              log                      = LoggerFactory.getLogger(PasswordSettingsContainerProvider.class);

    /**
     * Default RDN of password container object
     */
    public static final String        AD_DEFAULT_CONTAINER_RDN = "CN=Password Settings Container,CN=System";

    /**
     * Default object class for PSO
     */
    public static final String        PSO_FILTER               = "(objectClass=msDS-PasswordSettings)";

    /**
     * Template used to query policy
     */
    private LdapTemplate              ldapTemplate;

    /**
     * Timestamp of last query
     */
    private long                      lastTimeFetched          = 0;

    /**
     * Time between two reloads of the policy
     */
    private long                      refreshInterval          = 86400000L;

    /**
     * Ldap domain DN to read (eg: dc=example, dc=com), can be a relative DN if ContextSource is the domaine base DN
     */
    private String                    containerDN              = AD_DEFAULT_CONTAINER_RDN;

    /**
     * LDAP Filter, default should be OK
     */
    private String                    filter                   = PSO_FILTER;

    /**
     * The PSO's, key is suffix of PSO's DN (cn=xxx)
     */
    HashMap<String, PasswordSettings> policies                 = new HashMap<String, PasswordSettings>();

    @Override
    public Map<String, PasswordSettings> getAllPasswordSettings() {

        updatePasswordSettings(false);
        return policies;
    }

    @Override
    public PasswordSettings getPasswordSettings(String DN) {

        try {
            return getPasswordSettings(new DistinguishedName(DN));
        } catch (BadLdapGrammarException e) {
            log.warn("Unable to parse LDAP DN : [" + DN + "]. Returning null");
            return null;
        }

    }

    @Override
    public PasswordSettings getPasswordSettings(Name name) {

        if (!name.isEmpty()) {
            updatePasswordSettings(false);
            String suffix = name.get(name.size() - 1).toLowerCase();
            return policies.get(suffix);
        }
        return null;
    }

    @Override
    public void afterPropertiesSet() throws Exception {

        if (ldapTemplate == null) {
            throw new BeanInitializationException("contextSource cannot be null");
        }
        if (!updatePasswordSettings(true) && log.isInfoEnabled()) {
            log.info("PasswordPolicies has not been fetched although forceUpdate = true. Another reload attempt will be done at first query");
        }

    }

    /**
     * Domain Policy fetching, should be thread-safe
     * 
     * @return true if fetch has really been done
     */
    private synchronized boolean updatePasswordSettings(boolean forceUpdate) {

        if ((System.currentTimeMillis() <= lastTimeFetched + refreshInterval) && !forceUpdate && (!policies.isEmpty())) {
            return false;
        }

        if (log.isDebugEnabled()) {
            log.debug("Password policy will be read : " + ((policies.isEmpty()) ? " it has never been fetched." : "")
                    + ((forceUpdate) ? " Update has been forced." : ""));
            log.debug("LDAP filter used : " + filter);
            log.debug("Attributes fetched " + Arrays.toString(PasswordSettingsMapper.DEFAULT_DOMAIN_POLICY_ATTRS));
        }

        HashMap<String, PasswordSettings> policies = new HashMap<String, PasswordSettings>();

        SearchControls sc = new SearchControls();
        sc.setSearchScope(SearchControls.ONELEVEL_SCOPE);
        sc.setReturningObjFlag(true);
        sc.setReturningAttributes(PasswordSettingsMapper.PSO_ATTRS);

        ldapTemplate.search(containerDN, filter, sc, new PasswordSettingsMapper(policies, PasswordSettingsMapper.PSO_ATTRS));

        if (policies.isEmpty()) {
            log.warn("No Policy has been read from LDAP !! Are you sure that ACLs allows reading of the container");
            return false;
        }

        // Only override if a result has been read
        this.policies = policies;
        this.lastTimeFetched = System.currentTimeMillis();

        return true;
    }

    // Setters & Getters

    public void setContextSource(ContextSource cs) {

        this.ldapTemplate = new LdapTemplate(cs);
    }

    public void setRefreshInterval(long refreshInterval) {

        this.refreshInterval = refreshInterval;
    }

    public long getRefreshInterval() {

        return refreshInterval;
    }

    public void setContainerDN(String containerDN) {

        this.containerDN = containerDN;
    }

    public String getContainerDN() {

        return containerDN;
    }

    
    public long getLastTimeFetched() {
    
        return lastTimeFetched;
    }

}
