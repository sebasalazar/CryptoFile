package cl.sebastian.cmd.crypto.utils;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.Serializable;
import java.util.Arrays;

/**
 *
 * @author Sebastián Salazar Molina
 */
public class CryptoUtils implements Serializable {

    private static final long serialVersionUID = 5318510220271195136L;

    private static final String BASE_KEY = "e^(i*PI)+1=0";
    private static final String ALGORITHM = "Blowfish";
    private static final String OPERATION_MODE = "Blowfish/CBC/PKCS5Padding";
    private static final Logger LOGGER = LoggerFactory.getLogger(CryptoUtils.class);

    /**
     * Clase utilitaria, no debería instanciarse nunca.
     */
    private CryptoUtils() {
        throw new AssertionError();
    }

    /**
     *
     * @param text Texto a pasar por el hash
     * @return El texto hasheado en SHA512 o un String vacío en cualquier otro
     * caso.
     */
    public static String hashSha512(final String text) {
        String hash = StringUtils.EMPTY;
        try {
            if (StringUtils.isNotBlank(text)) {
                hash = DigestUtils.sha512Hex(text);
            }
        } catch (Exception e) {
            hash = StringUtils.EMPTY;
            LOGGER.error("Error al hashear en SHA512: {}", e.toString());
        }
        return hash;
    }

    /**
     *
     * @param text Texto a pasar por el hash
     * @param salt Salto para varíar el hash generado.
     * @return El texto hasheado en SHA512 o un String vacío en cualquier otro
     * caso.
     */
    public static String hashSha512(final String text, final String salt) {
        String hash = StringUtils.EMPTY;
        try {
            if (StringUtils.isNotBlank(text) && StringUtils.isNotBlank(salt)) {
                String newText = StringUtils.trimToEmpty(String.format("%s%s",
                        StringUtils.trimToEmpty(text),
                        StringUtils.trimToEmpty(salt)));
                hash = DigestUtils.sha512Hex(newText);
            }
        } catch (Exception e) {
            hash = StringUtils.EMPTY;
            LOGGER.error("Error al hashear en SHA512: {}", e.toString());
        }
        return hash;
    }

    /**
     *
     * @param text String con el texto a hashear
     * @return El hash sha256 del texto o vacío en cualquier otro caso.
     */
    public static String hashSha256(final String text) {
        String hash = StringUtils.EMPTY;
        try {
            if (StringUtils.isNotBlank(text)) {
                hash = DigestUtils.sha256Hex(text);
            }
        } catch (Exception e) {
            hash = StringUtils.EMPTY;
            LOGGER.error("Error al hashear en Sha256: {}", e.toString());
        }
        return hash;
    }

    /**
     *
     * @param text String con el texto a hashear
     * @return El hash sha1 del texto o vacío en cualquier otro caso.
     */
    public static String hashSha1(String text) {
        String hash = StringUtils.EMPTY;
        try {
            if (StringUtils.isNotBlank(text)) {
                hash = DigestUtils.sha1Hex(text);
            }
        } catch (Exception e) {
            hash = StringUtils.EMPTY;
            LOGGER.error("Error al hashear en Sha1: {}", e.toString());
        }
        return hash;
    }

    /**
     *
     * @param key Llave de cifrado
     * @param message Mensaje a cifrar
     * @return El mensaje cifrado en Blowfish, usando la llave o vacío en
     * cualquier otro caso.
     */
    public static String encrypt(final String key, final String message) {
        String result = StringUtils.EMPTY;
        try {
            if (StringUtils.isNotBlank(key) && StringUtils.isNotEmpty(message)) {
                // Mejorar la versión adjuntando el vector de inicialización
                byte[] biv = new byte[8];
                Arrays.fill(biv, (byte) 0);
                IvParameterSpec iv = new IvParameterSpec(biv);

                byte[] data = key.getBytes("UTF-8");
                SecretKeySpec ks = new SecretKeySpec(data, ALGORITHM);
                Cipher cipher = Cipher.getInstance(OPERATION_MODE);
                cipher.init(Cipher.ENCRYPT_MODE, ks, iv);
                byte[] out = cipher.doFinal(message.getBytes("UTF-8"));
                result = Hex.encodeHexString(out);
            }
        } catch (Exception e) {
            result = StringUtils.EMPTY;
            LOGGER.error("Error al encrypt texto: {}", e.toString());
            LOGGER.debug("Error al encrypt texto: {}", e.toString(), e);
        }
        return result;
    }

    /**
     *
     * @param key Llave de cifrado
     * @param message Mensaje cifrado en Blowfish
     * @return El texto claro del cifrado Blowfish o vacío en cualquier otro
     * caso.
     */
    public static String decrypt(final String key, final String message) {
        String result = StringUtils.EMPTY;
        try {
            if (StringUtils.isNotBlank(key) && StringUtils.isNotEmpty(message)) {
                // Mejorar la versión adjuntando el vector de inicialización
                byte[] biv = new byte[8];
                Arrays.fill(biv, (byte) 0);
                IvParameterSpec iv = new IvParameterSpec(biv);

                byte[] data = key.getBytes("UTF-8");
                SecretKeySpec ks = new SecretKeySpec(data, ALGORITHM);
                Cipher cipher = Cipher.getInstance(OPERATION_MODE);
                cipher.init(Cipher.DECRYPT_MODE, ks, iv);
                byte[] out = cipher.doFinal(Hex.decodeHex(message.toCharArray()));
                result = new String(out);
            }
        } catch (Exception e) {
            result = StringUtils.EMPTY;
            LOGGER.error("Error al decrypt texto: {}", e.toString());
            LOGGER.debug("Error al decrypt texto: {}", e.toString(), e);
        }
        return result;
    }

    /**
     *
     * @param vector Texto que servirá como vector de inicialización.
     * @param key Llave de cifrado.
     * @param message Mensaje a cifrar.
     * @return El mensaje cifrado en Blowfish, usando la llave o vacío en
     * cualquier otro caso.
     */
    public static String encrypt(final String vector, final String key, final String message) {
        String result = StringUtils.EMPTY;
        try {
            if (StringUtils.isNotBlank(vector) && StringUtils.isNotBlank(key) && StringUtils.isNotEmpty(message)) {
                byte[] biv = Arrays.copyOf(vector.getBytes("UTF-8"), 8);
                IvParameterSpec iv = new IvParameterSpec(biv);

                byte[] data = key.getBytes("UTF-8");
                SecretKeySpec ks = new SecretKeySpec(data, ALGORITHM);
                Cipher cipher = Cipher.getInstance(OPERATION_MODE);
                cipher.init(Cipher.ENCRYPT_MODE, ks, iv);
                byte[] out = cipher.doFinal(message.getBytes("UTF-8"));
                result = Hex.encodeHexString(out);
            }
        } catch (Exception e) {
            result = StringUtils.EMPTY;
            LOGGER.error("Error al encrypt texto: {}", e.toString());
            LOGGER.debug("Error al encrypt texto: {}", e.toString(), e);
        }
        return result;
    }

    /**
     *
     * @param vector Texto que servirá como vector de inicialización.
     * @param key Llave de cifrado.
     * @param message Mensaje cifrado en Blowfish.
     * @return El texto claro del cifrado Blowfish o vacío en cualquier otro
     * caso.
     */
    public static String decrypt(final String vector, final String key, final String message) {
        String result = StringUtils.EMPTY;
        try {
            if (StringUtils.isNotBlank(vector) && StringUtils.isNotBlank(key) && StringUtils.isNotEmpty(message)) {
                byte[] biv = Arrays.copyOf(vector.getBytes("UTF-8"), 8);
                IvParameterSpec iv = new IvParameterSpec(biv);

                byte[] data = key.getBytes("UTF-8");
                SecretKeySpec ks = new SecretKeySpec(data, ALGORITHM);
                Cipher cipher = Cipher.getInstance(OPERATION_MODE);
                cipher.init(Cipher.DECRYPT_MODE, ks, iv);
                byte[] out = cipher.doFinal(Hex.decodeHex(message.toCharArray()));
                result = new String(out);
            }
        } catch (Exception e) {
            result = StringUtils.EMPTY;
            LOGGER.error("Error al decrypt texto: {}", e.toString());
            LOGGER.debug("Error al decrypt texto: {}", e.toString(), e);
        }
        return result;
    }

    /**
     *
     * @param message Mensaje a cifrar
     * @return Texto cifrado usando una llave fija (es inseguro).
     */
    public static String encrypt(final String message) {
        return encrypt(BASE_KEY, message);
    }

    /**
     *
     * @param message Mensaje a descifrar
     * @return Texto descifrado usando una llave fija (es inseguro).
     */
    public static String decrypt(final String message) {
        return decrypt(BASE_KEY, message);
    }
}
