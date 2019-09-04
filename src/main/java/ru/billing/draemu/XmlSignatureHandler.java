package ru.billing.draemu;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.io.IOUtils;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.w3c.dom.Element;
import org.w3c.dom.Attr;

import org.xml.sax.SAXException;


import org.apache.xml.security.utils.IdResolver;


//import com.eixox.security.X509CertificateKeySelector;
//import com.eixox.security.X509CertificateWithKey;

/**
 * An XML Signature handler that can sign with x509 certificates xml documents.
 *
 * @author Rodrigo Portela
 *
 */

public class XmlSignatureHandler {

    private static final String PRIVATE_KEY_ALIAS = "nexign.provGW";
    private static final String PRIVATE_KEY_PASS = "provgw";
    private static final String KEY_STORE_PASS = "provgw";
    private static final String KEY_STORE_TYPE = "JKS";
    String iFile;
    String oFile;
    String cFile;

    private final DocumentBuilderFactory builderFactory;
    private final TransformerFactory transformerFactory;
    private final XMLSignatureFactory signatureFactory;
    private final DigestMethod digestMethod;
    private final List<Transform> transformList;
    private final CanonicalizationMethod canonicalizationMethod;
    private final SignatureMethod signatureMethod;
    private final KeyInfoFactory keyInfoFactory;
   // public final X509CertificateWithKey certificateWithKey = new X509CertificateWithKey();
   /* final KeyStore keyStore = loadKeyStore(new File(cFile));
    final Key privateKey = keyStore.getKey(PRIVATE_KEY_ALIAS, PRIVATE_KEY_PASS.toCharArray());
    final X509Certificate cert = (X509Certificate)keyStore.getCertificate(PRIVATE_KEY_ALIAS);
    final PublicKey publicKey = cert.getPublicKey();*/

    KeyStore keyStore;
    Key privateKey ;
    X509Certificate cert ;
    PublicKey publicKey;


    public Document document;
    public String referenceUri = "#Body";

    public XmlSignatureHandler(String iFile,  String cFile, String oFile) throws Exception {
        this.iFile=iFile;
        this.cFile=cFile;
        this.oFile=oFile;

         keyStore = loadKeyStore(new File(cFile));
         privateKey = keyStore.getKey(PRIVATE_KEY_ALIAS, PRIVATE_KEY_PASS.toCharArray());
         cert = (X509Certificate)keyStore.getCertificate(PRIVATE_KEY_ALIAS);
         publicKey = cert.getPublicKey();

        this.builderFactory = DocumentBuilderFactory.newInstance();
        this.builderFactory.setNamespaceAware(true);
        this.transformerFactory = TransformerFactory.newInstance();
        this.signatureFactory = XMLSignatureFactory.getInstance("DOM");
        this.digestMethod = signatureFactory.newDigestMethod(DigestMethod.SHA1, null);
        this.transformList = new ArrayList<Transform>(2);

        this.transformList.add(
                signatureFactory.newTransform(
                        Transform.ENVELOPED,
                        (TransformParameterSpec) null));

        this.transformList.add(
                signatureFactory.newTransform(
                        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments",
                        (TransformParameterSpec) null));

        this.canonicalizationMethod = this.signatureFactory.newCanonicalizationMethod(
                CanonicalizationMethod.INCLUSIVE,
                (C14NMethodParameterSpec) null);

        this.signatureMethod = this.signatureFactory.newSignatureMethod(SignatureMethod.RSA_SHA1, null);
        this.keyInfoFactory = this.signatureFactory.getKeyInfoFactory();

    }

    private static KeyStore loadKeyStore(File privateKeyFile) throws Exception {
        final InputStream fileInputStream = new FileInputStream(privateKeyFile);
        try {
            final KeyStore keyStore = KeyStore.getInstance(KEY_STORE_TYPE);
            keyStore.load(fileInputStream, KEY_STORE_PASS.toCharArray());
            return keyStore;
        }
        finally {
            IOUtils.closeQuietly(fileInputStream);
        }
    }

    public synchronized void sign()
            throws MarshalException,
            XMLSignatureException,
            KeyException, IOException {

        if (this.document == null)
            throw new RuntimeException("Can't sign a NULL document");

        //Element root = docCanonical.getDocumentElement();
        Element header = document.createElementNS("http://schemas.xmlsoap.org/soap/envelope/","soapenv:Header");
        document.getFirstChild().appendChild(header);

        NodeList elList = this.document.getElementsByTagName("soapenv:Body");
        if (elList != null && elList.getLength() > 0) {
            Attr id = ((Element)elList.item(0)).getAttributeNode("Id");
            IdResolver.registerElementById((Element)elList.item(0), id);
            //log.debug("registered id: " + id + " for element: " + (Element)elList.item(0));
        }
        Reference reference = this.signatureFactory.newReference(
                referenceUri,
                this.digestMethod,
                this.transformList,
                null,
                null);


        SignedInfo signedInfo = this.signatureFactory.newSignedInfo(
                this.canonicalizationMethod,
                this.signatureMethod,
                Collections.singletonList(reference));


        // Create the KeyInfo containing the X509Data.
        X509Data xd = this.keyInfoFactory.newX509Data(
                Collections.singletonList(this.cert));



        KeyValue keyValue = this.keyInfoFactory.newKeyValue(publicKey);

        List x509list = new ArrayList();

        x509list.add(xd);
        x509list.add(keyValue);


    //    KeyInfo keyInfo = this.keyInfoFactory.newKeyInfo(Collections.singletonList(xd));

        KeyInfo keyInfo = this.keyInfoFactory.newKeyInfo(x509list);

        XMLSignature signature = this.signatureFactory.newXMLSignature(
                signedInfo,
                keyInfo);

        System.out.println(signature.getSignedInfo().toString());
/*
        DOMSignContext signingContext = new DOMSignContext(
                this.privateKey,
                document.getDocumentElement());
*/
        DOMSignContext signingContext = new DOMSignContext(
                this.privateKey,
                header);
        //signingContext.putNamespacePrefix(XMLSignature.XMLNS,"ds");
        signingContext.setDefaultNamespacePrefix("ds");


        signature.sign(signingContext);

        System.out.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");


       // System.out.println((signature.getSignedInfo().getCanonicalizationMethod().getAlgorithm()));
        Reader r = new InputStreamReader(signature.getSignedInfo().getCanonicalizedData());
        StringWriter sw = new StringWriter();
        char[] buffer = new char[1024];
        for (int n; (n = r.read(buffer)) != -1; )
            sw.write(buffer, 0, n);
        String str = sw.toString();
        System.out.println(str);


        System.out.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    }

    public synchronized void write(OutputStream os)
            throws TransformerException {
        Transformer trans = this.transformerFactory.newTransformer();
        DOMSource domSource = new DOMSource(document);
        StreamResult streamResult = new StreamResult(os);
        trans.transform(domSource, streamResult);

    }



    public void loadDocument(InputStream is)
            throws SAXException,
            IOException,
            ParserConfigurationException {
        this.document = this.builderFactory.newDocumentBuilder().parse(is);
    }

    public void loadDocument(String uri)
            throws SAXException,
            IOException,
            ParserConfigurationException {
        this.document = this.builderFactory.newDocumentBuilder().parse(uri);
    }

    public void loadDocument(File file)
            throws SAXException,
            IOException,
            ParserConfigurationException {
        this.document = this.builderFactory.newDocumentBuilder().parse(file);
    }

    public  void output( String fileName) throws IOException {
        final OutputStream fileOutputStream = new FileOutputStream(fileName);
        try {
            write(fileOutputStream);
        } catch (TransformerException e) {
            e.printStackTrace();
        }

    }
}