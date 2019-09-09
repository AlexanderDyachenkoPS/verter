package ru.billing.verter;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

public class VerterParameters {

    private String          KEYFILE;
    private String          PRIVATE_KEY_ALIAS;
    private String          PRIVATE_KEY_PASS;
    private String          KEY_STORE_PASS;
    private String          KEY_STORE_TYPE;
    private String          LISTEN_PORT;
    private String          VALIDATOR_URI;
    private String          SIGNER_URI;
    private String          HLR_URI;
    private KeyStore        KEYSTORE;
    private Key             PRIVATEKEY ;
    private X509Certificate CERTIFICATE ;
    private PublicKey       PUBLICKEY;

    private Logger          logger;
    private String          logPrefix = "Params: ";


    public VerterParameters(     String          iKEYFILE,
                                 String          iPRIVATE_KEY_ALIAS,
                                 String          iPRIVATE_KEY_PASS,
                                 String          iKEY_STORE_PASS,
                                 String          iKEY_STORE_TYPE,
                                 String          iLISTEN_PORT,
                                 String          iVALIDATOR_URI,
                                 String          iSIGNER_URI,
                                 String          iHLR_URI,
                                 Logger          ilogger
                           ) throws Exception {
        setKEYFILE(iKEYFILE);
        setPRIVATE_KEY_ALIAS(iPRIVATE_KEY_ALIAS);
        setPRIVATE_KEY_PASS(iPRIVATE_KEY_PASS);
        setKEY_STORE_PASS(iKEY_STORE_PASS);
        setKEY_STORE_TYPE(iKEY_STORE_TYPE);
        setLISTEN_PORT(iLISTEN_PORT);
        setVALIDATOR_URI(iVALIDATOR_URI);
        setSIGNER_URI(iSIGNER_URI);
        setHLR_URI(iHLR_URI);
        this.logger = ilogger;

        KEYSTORE    = loadKeyStore(new File(this.KEYFILE));
        PRIVATEKEY  = this.KEYSTORE.getKey(this.PRIVATE_KEY_ALIAS, this.PRIVATE_KEY_PASS.toCharArray());
        CERTIFICATE = (X509Certificate)this.KEYSTORE.getCertificate(this.PRIVATE_KEY_ALIAS);
        PUBLICKEY   = this.CERTIFICATE.getPublicKey();
        logInfoMessage("All parameters are loaded.");

    }

    private void logInfoMessage (String msg) {logger.info(logPrefix+msg);}

    private void logDebugMessage (String msg) {logger.debug(logPrefix+msg);}

    private KeyStore loadKeyStore(File privateKeyFile) throws Exception {
        logInfoMessage("Load RSA keys from "+privateKeyFile.getAbsolutePath());
        final InputStream fileInputStream = new FileInputStream(privateKeyFile);
        try {
            KeyStore keyStore = KeyStore.getInstance(this.KEY_STORE_TYPE);
            keyStore.load(fileInputStream, this.KEY_STORE_PASS.toCharArray());
            return keyStore;
        }
        finally {
            IOUtils.closeQuietly(fileInputStream);
        }
    }

    public String getKEYFILE() {
        return KEYFILE;
    }

    private void setKEYFILE(String KEYFILE) {
        this.KEYFILE = KEYFILE;
    }

    public String getPRIVATE_KEY_ALIAS() {
        return PRIVATE_KEY_ALIAS;
    }

    private void setPRIVATE_KEY_ALIAS(String PRIVATE_KEY_ALIAS) {
        this.PRIVATE_KEY_ALIAS = PRIVATE_KEY_ALIAS;
    }

    public String getPRIVATE_KEY_PASS() {
        return PRIVATE_KEY_PASS;
    }

    private void setPRIVATE_KEY_PASS(String PRIVATE_KEY_PASS) {
        this.PRIVATE_KEY_PASS = PRIVATE_KEY_PASS;
    }

    public String getKEY_STORE_PASS() {
        return KEY_STORE_PASS;
    }

    private void setKEY_STORE_PASS(String KEY_STORE_PASS) {
        this.KEY_STORE_PASS = KEY_STORE_PASS;
    }

    public String getKEY_STORE_TYPE() {
        return KEY_STORE_TYPE;
    }

    private void setKEY_STORE_TYPE(String KEY_STORE_TYPE) {
        this.KEY_STORE_TYPE = KEY_STORE_TYPE;
    }

    public String getLISTEN_PORT() {
        return LISTEN_PORT;
    }

    private void setLISTEN_PORT(String LISTEN_PORT) {
        this.LISTEN_PORT = LISTEN_PORT;
    }

    public String getVALIDATOR_URI() {
        return VALIDATOR_URI;
    }

    private void setVALIDATOR_URI(String VALIDATOR_URI) {
        this.VALIDATOR_URI = VALIDATOR_URI;
    }

    public String getSIGNER_URI() {
        return SIGNER_URI;
    }

    private void setSIGNER_URI(String SIGNER_URI) {
        this.SIGNER_URI = SIGNER_URI;
    }

    public String getHLR_URI() {
        return HLR_URI;
    }

    public KeyStore getKEYSTORE() {
        return KEYSTORE;
    }

    public Key getPRIVATEKEY() {
        return PRIVATEKEY;
    }

    public X509Certificate getCERTIFICATE() {
        return CERTIFICATE;
    }

    public PublicKey getPUBLICKEY() {
        return PUBLICKEY;
    }

    private void setHLR_URI(String HLR_URI) {
        this.HLR_URI = HLR_URI;
    }

}
