package ru.billing.verter;

import java.io.*;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.io.IOUtils;
import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.ElementProxy;
import org.w3c.dom.*;

import static org.apache.xml.security.transforms.Transforms.TRANSFORM_C14N_OMIT_COMMENTS;


public class CreateSignatureFile {

    private static final String PRIVATE_KEY_ALIAS = "nexign.provGW";
    private static final String PRIVATE_KEY_PASS = "provgw";
    private static final String KEY_STORE_PASS = "provgw";
    private static final String KEY_STORE_TYPE = "JKS";

    String iFile;
    String oFile;
    String cFile;

    CreateSignatureFile ( String iFile,  String cFile, String oFile) {
        this.iFile=iFile;
        this.cFile=cFile;
        this.oFile=oFile;

    }

    public  void signFile () throws Exception {
        final InputStream fileInputStream = new FileInputStream(iFile);

       // byte[] array =  Files.readAllBytes(Paths.get("c:\\UCELL\\data\\nxbody.xml"));
      //  String encodedString = Base64.getEncoder().encodeToString(array);
      //  System.out.println(encodedString);


        // String encodedString = Base64.getEncoder().encodeToString(IOUtils.toByteArray(fileInputStream));
        try {
            output(signFile(fileInputStream, new File(cFile)), oFile);

        }
        finally {
            IOUtils.closeQuietly(fileInputStream);
        }
    }

    public static ByteArrayOutputStream signFile(InputStream xmlFile, File privateKeyFile) throws Exception {

        DocumentBuilderFactory dbf =  DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(xmlFile);


        Init.init();
       // System.setProperty("org.apache.xml.security.ignoreLineBreaks","true");
      //  Field f = XMLUtils.class.getDeclaredField("ignoreLineBreaks");
      //  f.setAccessible(true);
       //f.set(null, Boolean.TRUE);
        Canonicalizer c14nizer =
                Canonicalizer.getInstance(TRANSFORM_C14N_OMIT_COMMENTS);

        c14nizer.canonicalizeSubtree(doc);

        DocumentBuilder dbCanonical = dbf.newDocumentBuilder();

        Document docCanonical = dbCanonical.parse(new ByteArrayInputStream(c14nizer.canonicalizeSubtree(doc)));

        NodeList nl = docCanonical.getElementsByTagNameNS("http://schemas.xmlsoap.org/soap/envelope/","soapenv:Body");
        Node rootNode = docCanonical.getFirstChild();
        NodeList rootChilds = rootNode.getChildNodes();
        NamedNodeMap nm = rootChilds.item(0).getAttributes();
          Attr id = (Attr) nm.item(0);
           Element body = (Element) rootChilds.item(0);
           body.setIdAttributeNode(id,true);
         //IdResolver.registerElementById(body,id);

        Element root = docCanonical.getDocumentElement();
        Element header = docCanonical.createElementNS("http://schemas.xmlsoap.org/soap/envelope/","soapenv:Header");

        ElementProxy.setDefaultPrefix( Constants.SignatureSpecNS, "ds");

        final KeyStore keyStore = loadKeyStore(privateKeyFile);


        //final XMLSignature sig = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_RSA);
        final XMLSignature sig = new XMLSignature (docCanonical, "", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1,TRANSFORM_C14N_OMIT_COMMENTS);
        sig.setXPathNamespaceContext("xmlns:ds","http://www.w3.org/2000/09/xmldsig#");


        final Transforms transforms = new Transforms(docCanonical);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);
        transforms.setSecureValidation(true);



        sig.addDocument("#Body", transforms, Constants.ALGO_ID_DIGEST_SHA1);


        final Key privateKey = keyStore.getKey(PRIVATE_KEY_ALIAS, PRIVATE_KEY_PASS.toCharArray());
        final X509Certificate cert = (X509Certificate)keyStore.getCertificate(PRIVATE_KEY_ALIAS);
        System.out.println("============================================================");
        System.out.println(cert.getPublicKey().toString());
        System.out.println(cert.getIssuerUniqueID());
        System.out.println(cert.getIssuerDN());
        System.out.println(cert.getSubjectDN().toString());



        System.out.println("============================================================");
        sig.addKeyInfo(cert);
        sig.addKeyInfo(cert.getPublicKey());

        sig.sign(privateKey);

        System.out.println("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");

        DOMSource domSource = new DOMSource(sig.getSignedInfo().getElement());
        StringWriter writer = new StringWriter();
        StreamResult result = new StreamResult(writer);
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        transformer.transform(domSource, result);
        System.out.println(writer.toString());

        System.out.println("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");

        header.appendChild(sig.getElement());

        docCanonical.getFirstChild().appendChild(header);



        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      //  outputStream.write(Canonicalizer.getInstance(ALGO_ID_C14N_WITH_COMMENTS).canonicalizeSubtree(docCanonical));
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        org.apache.xml.security.utils.XMLUtils.outputDOM(docCanonical,baos);

        outputStream.write (baos.toByteArray());





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











  /*
        private static final String PRIVATE_KEY_ALIAS = "server-alias";
        private static final String PRIVATE_KEY_PASS = "changeit";
        private static final String KEY_STORE_PASS = "changeit";
        private static final String KEY_STORE_TYPE = "JKS";
    */




/*
        //////////
        System.out.println("????????????????????????????????");


        Init.init();
        XMLSignatureInput signatureInput = new XMLSignatureInput((Node) doc);
        Document transformDoc = db.newDocument();
        Transforms c14nTrans = new Transforms(transformDoc);
        transformDoc.appendChild(c14nTrans.getElement());
        c14nTrans.addTransform("http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments");
        XMLSignatureInput c14nResult = c14nTrans.performTransforms(signatureInput);
        byte outputBytes[] = c14nResult.getBytes();
        System.out.println("///////////////////");
        System.out.println(new String(outputBytes));
        System.out.println("????????????????????????????????");
        ////////

*/


//doc.getFirstChild().appendChild(header);
//System.out.println(rootChilds.item(rootChilds.item(1).getAttributes().toString() ));
// Attr a = doc.getElementsByTagNameNS()

//        ..body.getAttributeNode("Id");

// IdResolver.registerElementById(body,a);

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

