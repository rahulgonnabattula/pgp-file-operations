package in.zeta;

import in.zeta.openpgp.FileCryptoOperations;
import org.bouncycastle.openpgp.PGPException;

import java.io.IOException;
import java.security.Security;

/**
 * Copied from <a href="https://github.com/bcgit/bc-java/blob/master/pg/src/main/java/org/bouncycastle/openpgp/examples/KeyBasedFileProcessor.java">Official BouncyCastle documentation </a>
 */
@SuppressWarnings("java:S106")
public class Main {
    public static void main(String[] args)
        throws PGPException, IOException {
        if(args.length<3){
            System.out.println("Usage:  java -jar pgp-encrypt-file-0.1-shaded.jar <outputFilePath> <inputFilePath> <publicKeyPath>");
            System.exit(-1);
        }
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        String outputFileName = args[0];
        String inputFileName = args[1];
        String encKeyFileName = args[2];
        FileCryptoOperations.encryptFile(outputFileName, inputFileName, encKeyFileName, true);
    }
}