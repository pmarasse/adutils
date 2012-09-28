package net.archigny.adutils.password.util;

/**
 * Class used to type a set of inner exception that can occur during hash computation
 * 
 * @author Philippe MARASSE <philippe.marasse@ch-poitiers.fr>
 */
public class HashComputingException extends RuntimeException {

    /**
     * Serial ID
     */
    private static final long serialVersionUID = 1L;

    public HashComputingException(Throwable cause) {

        super(cause);
    }

    public HashComputingException(String message, Throwable cause) {

        super(message, cause);
    }

}
