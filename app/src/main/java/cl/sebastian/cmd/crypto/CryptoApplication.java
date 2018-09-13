package cl.sebastian.cmd.crypto;

import cl.sebastian.cmd.crypto.service.AppService;
import java.io.File;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class CryptoApplication implements CommandLineRunner {

    private final static Logger LOGGER = LoggerFactory.getLogger(CryptoApplication.class);

    @Autowired
    public AppService appService;

    public static void main(String[] args) {
        SpringApplication.run(CryptoApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        LOGGER.info("EXECUTING : command line runner");

        if (args.length > 3) {
            String type = StringUtils.trimToEmpty(args[0]);
            String key = StringUtils.trimToEmpty(args[1]);
            String input = StringUtils.trimToEmpty(args[2]);
            String output = StringUtils.trimToEmpty(args[3]);

            File file;
            if (StringUtils.containsIgnoreCase(type, "enc")) {
                file = appService.encryptFile(key, input, output);
            } else {
                file = appService.decryptFile(key, input, output);
            }

            if (file != null && file.isFile()) {
                LOGGER.info("Archivo generado en '{}'", file.getAbsolutePath());
            } else {
                LOGGER.error("Hubo error al cifrar");
            }
        }

    }

}
