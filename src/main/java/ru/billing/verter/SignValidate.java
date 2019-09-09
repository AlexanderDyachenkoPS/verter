package ru.billing.verter;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.X509Certificate;

import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.io.IOUtils;
import org.apache.xml.security.Init;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.utils.IdResolver;
import org.slf4j.Logger;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

public class SignValidate {

    VerterParameters verterParameters;
    private Logger logger;
    private String          logPrefix = "Signature Validator: ";


    SignValidate (VerterParameters iverterParameters,Logger ilogger){
        this.verterParameters=iverterParameters;
        this.logger = ilogger;
    }

    private void logInfoMessage (String msg) {logger.info(logPrefix+msg);}

    private void logDebugMessage (String msg) {logger.debug(logPrefix+msg);}


    public  void valSig (InputStream is, HttpServletResponse response) throws IOException {
        Init.init();
        javax.xml.parsers.DocumentBuilderFactory dbf =
                javax.xml.parsers.DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        javax.xml.parsers.DocumentBuilder db = null;


        try {
            db = dbf.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            logInfoMessage("HA HA HA. I have to go to the dump");
            logInfoMessage(e.getMessage());
            response.getWriter().println(e.getMessage());
        }
        try {

            Document doc = db.parse(is);

            XPathFactory xpf = XPathFactory.newInstance();
            XPath xpath = xpf.newXPath();
            xpath.setNamespaceContext(new DSNamespaceContext());
            String expression = "//ds:Signature[1]";
            Element sigElement =
                    (Element) xpath.evaluate(expression, doc, XPathConstants.NODE);
        XMLSignature signature =
                    new XMLSignature(sigElement, "");


            String expressionBody = "//soapenv:Body";
            Element bodyElement =
                    (Element) xpath.evaluate(expressionBody, doc, XPathConstants.NODE);

            Attr id = bodyElement.getAttributeNode("Id") ;
            IdResolver.registerElementById(bodyElement,id);


            KeyInfo ki = signature.getKeyInfo();
            logInfoMessage("================================signature.getSignatureValue()================================");

            String svStr = new String(signature.getSignatureValue());
            logInfoMessage(svStr);
            logInfoMessage("================================signature.getSignatureValue()================================");

            if (ki != null) {
                if (ki.containsX509Data()) {
                    logInfoMessage("Could find a X509Data element in the KeyInfo");
                    response.getWriter().println("Could find a X509Data element in the KeyInfo");

                }
                X509Certificate cert = signature.getKeyInfo().getX509Certificate();
                if (cert != null) {
                    logInfoMessage("The XML signature in file "

                            + (signature.checkSignatureValue(cert)
                            ? "valid (good)"  : "invalid !!!!! (bad)"));
                            response.getWriter().println("The XML signature in file "

                                    + (signature.checkSignatureValue(cert)
                                    ? "valid (good)"  : "invalid !!!!! (bad)"));
                } else {
                    logInfoMessage("Did not find a Certificate");
                    PublicKey pk = signature.getKeyInfo().getPublicKey();
                    if (pk != null) {
                        logInfoMessage("The XML signature in file "

                                + (signature.checkSignatureValue(pk)
                                ? "valid (good)" : "invalid !!!!! (bad)"));
                        response.getWriter().println("The XML signature in file "

                                + (signature.checkSignatureValue(pk)
                                ? "valid (good)" : "invalid !!!!! (bad)"));
                    } else {
                        logInfoMessage(
                                "Did not find a public key, so I can't check the signature");
                        response.getWriter().println("Did not find a public key, so I can't check the signature");
                    }
                }
            } else {
                logInfoMessage("Did not find a KeyInfo");
                response.getWriter().println("Did not find a KeyInfo");

            }
        } catch (SAXException e) {
            logInfoMessage("HA HA HA. I have to go to the dump");
            logInfoMessage(e.getMessage());
            response.getWriter().println(e.getMessage());
        } catch (IOException e) {
            logInfoMessage("HA HA HA. I have to go to the dump");
            logInfoMessage(e.getMessage());
            response.getWriter().println(e.getMessage());
        } catch (XPathExpressionException e) {
            logInfoMessage("HA HA HA. I have to go to the dump");
            logInfoMessage(e.getMessage());
            response.getWriter().println(e.getMessage());
        } catch (XMLSignatureException e) {
            logInfoMessage("HA HA HA. I have to go to the dump");
            logInfoMessage(e.getMessage());
            response.getWriter().println(e.getMessage());
        } catch (XMLSecurityException e) {
            logInfoMessage("HA HA HA. I have to go to the dump");
            logInfoMessage(e.getMessage());
            response.getWriter().println(e.getMessage());
        }

    }

}