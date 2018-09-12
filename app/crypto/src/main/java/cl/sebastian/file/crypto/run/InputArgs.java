package cl.sebastian.file.crypto.run;

import java.io.File;
import java.io.Serializable;
import picocli.CommandLine;
import picocli.CommandLine.Option;

/**
 *
 * @author seba
 */
public class InputArgs implements Serializable {

    private static final long serialVersionUID = 3335842662629516288L;

    @Option(names = { "-p", "--password" }, paramLabel = "PASSWORD", description = "La constraseña usada para cifrar")
    private String password = null;
    @Option(names = { "-enc", "--encrypt" }, paramLabel = "ENCRYPT", description = "Operación de cifrado")
    private boolean encrypt = false;
    @CommandLine.Parameters(index = "1", description = "Documento (texto claro) a cifrar")
    private File inputFile = null;
    @CommandLine.Parameters(index = "2", description = "Documento cifrado")
    private File outputFile = null;
}
