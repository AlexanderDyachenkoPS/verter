package ru.billing.verter;

import java.io.*;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.commons.io.IOUtils;
import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.ElementProxy;
import org.apache.xml.security.utils.IdResolver;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class CreateSignature {

    private static final String PRIVATE_KEY_ALIAS = "nexign.provgw";
    private static final String PRIVATE_KEY_PASS = "provgw";
    private static final String KEY_STORE_PASS = "provgw";
    private static final String KEY_STORE_TYPE = "JKS";
/*
    private static final String PRIVATE_KEY_ALIAS = "server-alias";
    private static final String PRIVATE_KEY_PASS = "changeit";
    private static final String KEY_STORE_PASS = "changeit";
    private static final String KEY_STORE_TYPE = "JKS";
*/
    public static void aaa () throws Exception {
        final InputStream fileInputStream = new FileInputStream("c:\\UCELL\\data\\xml");
        try {
            output(signFile(fileInputStream, new File("c:\\UCELL\\data\\nexign_fin.keystore")), "c:\\UCELL\\data\\signed-test.xml");
        }
        finally {
            IOUtils.closeQuietly(fileInputStream);
        }
    }

    public static ByteArrayOutputStream signFile(InputStream xmlFile, File privateKeyFile) throws Exception {

        DocumentBuilderFactory dbf =  DocumentBuilderFactory.newInstance();

        dbf.setNamespaceAware(true);


        DocumentBuilder db = dbf.newDocumentBuilder();

        final Document doc = db.newDocument();

        doc.appendChild(doc.createComment(" Comment before "));
        Element envelope =
                doc.createElementNS("http://schemas.xmlsoap.org/soap/envelope/", "soapenv:Envelope");
        envelope.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:xsd", "http://www.w3.org/2001/XMLSchema");
        envelope.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance");
        doc.appendChild(envelope);


        Element body = doc.createElementNS("http://schemas.xmlsoap.org/soap/envelope/","soapenv:Body");
        body.setAttribute("Id", "Body");
        envelope.appendChild(body);


        Element request = doc.createElementNS("urn:siemens:names:prov:gw:SPML:2:0","spml:modifyRequest");
        request.setAttributeNS("http://www.w3.org/2001/XMLSchema-instance","xsi:schemaLocation","urn:siemens:names:prov:gw:SUBSCRIBER:1:0 subscriber-1.0.xsd");
        request.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:subscriber", "urn:siemens:names:prov:gw:SUBSCRIBER:1:0");
        request.setAttribute("requestID","0812114412398-1265476-725");
        body.appendChild(request);

        Attr a = body.getAttributeNode("Id");

        IdResolver.registerElementById(body,a);

        //db.setEntityResolver(XMLEntityResolver );

         //Document doc = db.parse(xmlFile);

/*
        <?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
	<soapenv:Body>
		<spml:modifyRequest requestID="0812114412398-1265476-7235348235" xsi:schemaLocation="urn:siemens:names:prov:gw:SUBSCRIBER:1:0 subscriber-1.0.xsd" xmlns:spml="urn:siemens:names:prov:gw:SPML:2:0" xmlns:subscriber="urn:siemens:names:prov:gw:SUBSCRIBER:1:0">
			<version>SUBSCRIBER_v10</version>
			<objectclass>Subscriber</objectclass>
			<identifier>434051801331138</identifier>
			<modification operation="setoradd" xmlns:ns1="urn:siemens:names:prov:gw:SUBSCRIBER:1:0">
				<valueObject xsi:type="ns1:HLR">
					<clir>1</clir>
				</valueObject>
			</modification>
		</spml:modifyRequest>
	</soapenv:Body>
</soapenv:Envelope>

*/


/*
        final DocumentBuilder documentBuilder = dbf.newDocumentBuilder();
        final Document doc = documentBuilder.newDocument();
        Element root = doc.createElement("Root");
        doc.appendChild(root);
        final Element anElement = doc.createElement("InsideObject");
        anElement.appendChild(doc.createTextNode("A text in a box"));
        anElement.setAttribute("Id", "signed");
        anElement.setIdAttribute("Id", true);
        root.appendChild(anElement);
*/
        System.out.println("==============================");


        System.out.println("==============================");
        Init.init();
        ElementProxy.setDefaultPrefix(Constants.SignatureSpecNS, "ds");

        final KeyStore keyStore = loadKeyStore(privateKeyFile);
        final XMLSignature sig = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_RSA);
        final Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);

        sig.addDocument("#Body", transforms, Constants.ALGO_ID_DIGEST_SHA1);

        final Key privateKey = keyStore.getKey(PRIVATE_KEY_ALIAS, PRIVATE_KEY_PASS.toCharArray());
        final X509Certificate cert = (X509Certificate)keyStore.getCertificate(PRIVATE_KEY_ALIAS);
        sig.addKeyInfo(cert);
        sig.addKeyInfo(cert.getPublicKey());
        sig.sign(privateKey);
        doc.getDocumentElement().appendChild(sig.getElement());
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS).canonicalizeSubtree(doc));
        return outputStream;
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

    private static void output(ByteArrayOutputStream signedOutputStream, String fileName) throws IOException {
        final OutputStream fileOutputStream = new FileOutputStream(fileName);
        try {
            fileOutputStream.write(signedOutputStream.toByteArray());
            fileOutputStream.flush();
        }
        finally {
            IOUtils.closeQuietly(fileOutputStream);
        }
    }
}