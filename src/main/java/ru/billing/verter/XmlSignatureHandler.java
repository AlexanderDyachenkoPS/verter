package ru.billing.verter;

import java.io.*;
import java.security.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.crypto.MarshalException;
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
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.Init;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.w3c.dom.Element;
import org.w3c.dom.Attr;
import org.xml.sax.SAXException;
import org.apache.xml.security.utils.IdResolver;
import org.slf4j.Logger;


public class XmlSignatureHandler {

    private  DocumentBuilderFactory builderFactory;
    private  TransformerFactory transformerFactory;
    private  XMLSignatureFactory signatureFactory;
    private  DigestMethod digestMethod;
    private  List<Transform> transformList;
    private  CanonicalizationMethod canonicalizationMethod;
    private  SignatureMethod signatureMethod;
    private  KeyInfoFactory keyInfoFactory;
    private VerterParameters verterParameters;

    private Logger          logger;
    private String          logPrefix = "Signature Builder: ";


    public Document document;
    public String referenceUri = "#Body";

    public XmlSignatureHandler(VerterParameters iverterParameters, Logger ilogger) throws Exception {

        this.verterParameters=iverterParameters;
        this.logger = ilogger;


        Init.init();

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

    private void logInfoMessage (String msg) {logger.info(logPrefix+msg);}

    private void logDebugMessage (String msg) {logger.debug(logPrefix+msg);}

    public synchronized void sign()
            throws MarshalException,
            XMLSignatureException,
            KeyException, IOException {

        if (this.document == null)
            throw new RuntimeException("Can't sign a NULL document");

        Element header = document.createElementNS("http://schemas.xmlsoap.org/soap/envelope/","soapenv:Header");
        document.getFirstChild().appendChild(header);

        NodeList elList = this.document.getElementsByTagName("soapenv:Body");
        if (elList != null && elList.getLength() > 0) {
            Attr id = ((Element)elList.item(0)).getAttributeNode("Id");
            IdResolver.registerElementById((Element)elList.item(0), id);
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
                Collections.singletonList(this.verterParameters.getCERTIFICATE()));

        KeyValue keyValue = this.keyInfoFactory.newKeyValue(this.verterParameters.getPUBLICKEY());

        List x509list = new ArrayList();

        x509list.add(xd);
        x509list.add(keyValue);

        KeyInfo keyInfo = this.keyInfoFactory.newKeyInfo(x509list);

        XMLSignature signature = this.signatureFactory.newXMLSignature(
                signedInfo,
                keyInfo);

        logInfoMessage(signature.getSignedInfo().toString());

        DOMSignContext signingContext = new DOMSignContext(
                this.verterParameters.getPRIVATEKEY(),
                header);
        signingContext.setDefaultNamespacePrefix("ds");


        signature.sign(signingContext);

        Reader r = new InputStreamReader(signature.getSignedInfo().getCanonicalizedData());
        StringWriter sw = new StringWriter();
        char[] buffer = new char[1024];
        for (int n; (n = r.read(buffer)) != -1; )
            sw.write(buffer, 0, n);
        String str = sw.toString();
        logInfoMessage(str);

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


    public  void outputHTTP(ByteArrayOutputStream iByteArrayOutputStream) throws IOException {
        try {
            write(iByteArrayOutputStream);
        } catch (TransformerException e) {
            logInfoMessage("HA HA HA. I have to go to the dump");
            logInfoMessage(e.getMessage());
        }

    }
}