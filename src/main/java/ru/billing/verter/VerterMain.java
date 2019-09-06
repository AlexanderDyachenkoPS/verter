package ru.billing.verter;


import org.eclipse.jetty.server.Server;

public class VerterMain  {


    public static void main(String[] argv) throws Exception {


       final VerterParameters verterParameters= new VerterParameters(
                argv[0],       // iKEYFILE
                argv[1],       // iPRIVATE_KEY_ALIAS,
                argv[2],       // iPRIVATE_KEY_PASS,
                argv[3],       // iKEY_STORE_PASS,
                argv[4],       // iKEY_STORE_TYPE,
                argv[5],       // iLISTEN_PORT,
                argv[6],       // iVALIDATOR_URI,
                argv[7],       // iSIGNER_URI,
                argv[8]        // iHLR_URI
        );
//
   //     try {
            //CreateSignatureFile cr = new CreateSignatureFile();
  //          CreateSignatureFile cr = new CreateSignatureFile( argv[0], argv[1], argv[2]);
    //        cr.signFile();
   //     } catch (Exception e) {
   //         e.printStackTrace();
   //     } finally {System.out.println("SHIT!!!");}

    //    XmlSignatureHandler xs =new XmlSignatureHandler( argv[0], argv[1], argv[3]);

     //   xs.loadDocument(new FileInputStream(argv[0]));
    //    xs.sign();
     //   ByteArrayOutputStream baos = new ByteArrayOutputStream();
    //    xs.output(argv[3]);

    //   SignValidate sv = new SignValidate();
    //   sv.valSig(argv[4]);


       Integer serverPort = Integer.parseInt ( verterParameters.getLISTEN_PORT());
       Server server = new Server(serverPort);


        server.setHandler(new IncomingHandler(verterParameters));


       server.start();
        server.join();

    }

}
