package in.zeta.openpgp;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;

public class FileCryptoOperations {
    private FileCryptoOperations(){
        throw new java.lang.UnsupportedOperationException("FileCryptoOperations cannot be initialized");
    }
    public static void encryptFile(
            String          outputFileName,
            String          inputFileName,
            String          encKeyFileName,
            boolean         withIntegrityCheck)
            throws IOException, PGPException
    {
        try(OutputStream out = new BufferedOutputStream(Files.newOutputStream(Paths.get(outputFileName)))){
        PGPPublicKey encKey = readPublicKey(encKeyFileName);
        encryptFile(out, inputFileName, encKey, withIntegrityCheck);
        }
    }

    private static void encryptFile(
            OutputStream    out,
            String          fileName,
            PGPPublicKey    encKey,
            boolean         withIntegrityCheck)
            throws IOException {

        try
        {
            byte[] bytes = Files.readAllBytes(Paths.get(fileName));
            PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                    new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC"));

            encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"));

            try(OutputStream cOut = encGen.open(out, new byte[256]);
            OutputStream pOut = new PGPLiteralDataGenerator().open(
                cOut, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE,  new Date(), new byte[256])){


            pOut.write(bytes);
            }
            out.close();
        }
        catch (PGPException e)
        {
            e.printStackTrace();
            if (e.getUnderlyingException() != null)
            {
                e.getUnderlyingException().printStackTrace();
            }
        }
    }
    static PGPPublicKey readPublicKey(String fileName) throws IOException, PGPException
    {
        InputStream keyIn = new BufferedInputStream(Files.newInputStream(Paths.get(fileName)));
        PGPPublicKey pubKey = readPublicKey(keyIn);
        keyIn.close();
        return pubKey;
    }

    /**
     * A simple routine that opens a key ring file and loads the first available key
     * suitable for encryption.
     *
     * @param input data stream containing the public key data
     * @return the first public key found.
     * @throws IOException On error
     * @throws PGPException On PGP error
     */
    static PGPPublicKey readPublicKey(InputStream input) throws IOException, PGPException
    {
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());

        //
        // we just loop through the collection till we find a key suitable for encryption, in the real
        // world you would probably want to be a bit smarter about this.
        //

        Iterator<PGPPublicKeyRing> keyRingIter = pgpPub.getKeyRings();
        while (keyRingIter.hasNext())
        {
            PGPPublicKeyRing keyRing = keyRingIter.next();

            Iterator<PGPPublicKey> keyIter = keyRing.getPublicKeys();
            while (keyIter.hasNext())
            {
                PGPPublicKey key = keyIter.next();

                if (key.isEncryptionKey())
                {
                    return key;
                }
            }
        }

        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }

}
