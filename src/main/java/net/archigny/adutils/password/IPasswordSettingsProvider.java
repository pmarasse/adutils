package net.archigny.adutils.password;

import java.util.Map;

import javax.naming.Name;

public interface IPasswordSettingsProvider {

    /**
     * Retrieve the full map of all Password Settings Objects, the key is the
     * suffix of LDAP name (CN=xxx)
     * 
     * @return All PSOs
     */
    public Map<String, PasswordSettings> getAllPasswordSettings();

    /**
     * Lookup a password setting from a string as Distinguished Name
     * 
     * @param DN
     *            String representation of PSO Distinguished Name
     * @return Corresponding PSO or null
     */
    public PasswordSettings getPasswordSettings(final String DN);

    /**
     * Lookup a password settings object from a javax.Name value taking the
     * first element of suffix. (cn=xxx)
     * 
     * @param name
     *            PSO's Distinguished Name
     * @return Correspondinf PSO or null
     */
    public PasswordSettings getPasswordSettings(final Name name);
}
