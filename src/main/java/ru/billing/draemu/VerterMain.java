package ru.billing.draemu;


import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import java.sql.Timestamp;
import java.text.SimpleDateFormat;



import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;
import java.io.IOException;
import java.io.*;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;

public class VerterMain extends AbstractHandler {


    public static void main(String[] argv) throws Exception {



        try {
            //CreateSignatureFile cr = new CreateSignatureFile();
            CreateSignatureFile cr = new CreateSignatureFile( argv[0], argv[1], argv[2]);
            cr.signFile();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {System.out.println("SHIT!!!");}

        XmlSignatureHandler xs =new XmlSignatureHandler( argv[0], argv[1], argv[3]);

        xs.loadDocument(new FileInputStream(argv[0]));
        xs.sign();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        xs.output(argv[3]);

       SignValidate sv = new SignValidate();
       sv.valSig(argv[4]);

       // System.out.println (baos.toByteArray().toString());
       // SignValidate sv = new SignValidate();
       // sv.validateSign();

       // SignValidate vvv = new SignValidate();
       // vvv.validator();

       // Integer serverPort = Integer.parseInt ( argv[0]);
       // Server server = new Server(serverPort);


       // server.setHandler(new VerterMain());


       //server.start();
       // server.join();

    }
    public void handle (String target,
                        Request baseRequest,
                        HttpServletRequest request,
                        HttpServletResponse response)
            throws IOException, ServletException {

        System.out.println("GX>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");



try {
    CreateSignature cr = new CreateSignature();
    cr.aaa();
} catch (Exception e) {
    e.printStackTrace();
} finally {System.out.println("SHIT!!!");}

        Integer respCode = HttpServletResponse.SC_OK;

        response.setStatus(respCode);




        baseRequest.setHandled(true);
    }
}
