package net.archigny.adutils.password;

/**
 * Interface describing a simple provider of default password settings (ie: attribute constructed for a user is null)
 * 
 * @author Philippe MARASSE
 */
public interface IDefaultPasswordSettingsProvider {

    /**
     * Retrieve default password settings
     * 
     * @return Default password settings from an arbitrary source
     */
    public PasswordSettings getPasswordSettings();
    
}
