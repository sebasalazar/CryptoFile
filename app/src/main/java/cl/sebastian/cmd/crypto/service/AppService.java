package cl.sebastian.cmd.crypto.service;

import cl.sebastian.cmd.crypto.utils.CryptoUtils;
import java.io.File;
import java.nio.charset.Charset;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class AppService {

    private final static Logger LOGGER = LoggerFactory.getLogger(AppService.class);

    public File encryptFile(final String key, final String inputPath, final String outputPath) {
        File outFile = null;
        try {
            File inputFile = new File(inputPath);
            if (inputFile.isFile()) {
                String text = FileUtils.readFileToString(inputFile, Charset.forName("utf-8"));
                if (StringUtils.isNotBlank(key) && StringUtils.isNotBlank(text)) {
                    String encrypt = CryptoUtils.encrypt(key, text);
                    if (StringUtils.isNotBlank(encrypt)) {
                        outFile = new File(outputPath);
                        FileUtils.writeStringToFile(outFile, encrypt, Charset.forName("utf-8"));
                    }
                }
            }
        } catch (Exception e) {
            outFile = null;
            LOGGER.error("Error al cifrar: {}", e.toString());
            LOGGER.debug("Error al cifrar: {}", e.toString(), e);
        }
        return outFile;
    }

    public File decryptFile(final String key, final String inputPath, final String outputPath) {
        File outFile = null;
        try {
            File inputFile = new File(inputPath);
            if (inputFile.isFile()) {
                String text = FileUtils.readFileToString(inputFile, Charset.forName("utf-8"));
                if (StringUtils.isNotBlank(key) && StringUtils.isNotBlank(text)) {
                    String decrypt = CryptoUtils.decrypt(key, text);
                    if (StringUtils.isNotBlank(decrypt)) {
                        outFile = new File(outputPath);
                        FileUtils.writeStringToFile(outFile, decrypt, Charset.forName("utf-8"));
                    }
                }
            }
        } catch (Exception e) {
            outFile = null;
            LOGGER.error("Error al cifrar: {}", e.toString());
            LOGGER.debug("Error al cifrar: {}", e.toString(), e);
        }
        return outFile;
    }

}
