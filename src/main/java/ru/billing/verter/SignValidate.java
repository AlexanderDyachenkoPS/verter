package ru.billing.verter;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.X509Certificate;

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
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

public class SignValidate {

    VerterParameters verterParameters;

    SignValidate (VerterParameters iverterParameters){
        this.verterParameters=iverterParameters;
    }
    /*
    private static final String PRIVATE_KEY_ALIAS = "nexign.provGW";
    private static final String PRIVATE_KEY_PASS = "provgw";
    private static final String KEY_STORE_PASS = "provgw";
    private static final String KEY_STORE_TYPE = "JKS";
*/
    //
    // Synopsis: java Validate [document]
    //
    //	  where "document" is the name of a file containing the XML document
    //	  to be validated.
    //

    public  void valSig (InputStream is) {
        Init.init();
        javax.xml.parsers.DocumentBuilderFactory dbf =
                javax.xml.parsers.DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        javax.xml.parsers.DocumentBuilder db = null;

       // System.out.println("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");

        try {
            db = dbf.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
        }
        try {
          //  Document doc =
          //          db.parse(new FileInputStream(fileName));
            Document doc = db.parse(is);

            XPathFactory xpf = XPathFactory.newInstance();
            XPath xpath = xpf.newXPath();
            xpath.setNamespaceContext(new DSNamespaceContext());
            String expression = "//ds:Signature[1]";
            Element sigElement =
                    (Element) xpath.evaluate(expression, doc, XPathConstants.NODE);
/*
            XMLSignature signature =
                    new XMLSignature(sigElement, (new File(fileName)).toURI().toURL().toString());
*/
            XMLSignature signature =
                    new XMLSignature(sigElement, "");


            String expressionBody = "//soapenv:Body";
            Element bodyElement =
                    (Element) xpath.evaluate(expressionBody, doc, XPathConstants.NODE);

            Attr id = bodyElement.getAttributeNode("Id") ;
            IdResolver.registerElementById(bodyElement,id);
            //signature.addResourceResolver(new OfflineResolver());

            KeyInfo ki = signature.getKeyInfo();
            System.out.println("================================signature.getSignatureValue()================================");

            String svStr = new String(signature.getSignatureValue());
            System.out.println(svStr);
            System.out.println("================================signature.getSignatureValue()================================");

            if (ki != null) {
                if (ki.containsX509Data()) {
                    System.out.println("Could find a X509Data element in the KeyInfo");
                }
                X509Certificate cert = signature.getKeyInfo().getX509Certificate();
                if (cert != null) {
                    System.out.println("The XML signature in file "
                          //  + f.toURI().toURL().toString() + " is "
                            + (signature.checkSignatureValue(cert)
                            ? "valid (good)"  : "invalid !!!!! (bad)"));
                } else {
                    System.out.println("Did not find a Certificate");
                    PublicKey pk = signature.getKeyInfo().getPublicKey();
                    if (pk != null) {
                        System.out.println("The XML signature in file "
                               // + f.toURI().toURL().toString() + " is "
                                + (signature.checkSignatureValue(pk)
                                ? "valid (good)" : "invalid !!!!! (bad)"));
                    } else {
                        System.out.println(
                                "Did not find a public key, so I can't check the signature");
                    }
                }
            } else {
                System.out.println("Did not find a KeyInfo");
            }





        } catch (SAXException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (XPathExpressionException e) {
            e.printStackTrace();
        } catch (XMLSignatureException e) {
            e.printStackTrace();
        } catch (XMLSecurityException e) {
            e.printStackTrace();
        }

    }

}