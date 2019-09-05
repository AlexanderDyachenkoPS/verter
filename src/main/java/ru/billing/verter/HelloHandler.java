package ru.billing.verter;

import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class HelloHandler extends AbstractHandler
{

    VerterParameters verterParameters;
    HelloHandler(VerterParameters iverterParameters) {
        this.verterParameters = iverterParameters;
    }
    public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException
    {
        try {
            if (target.toString().equals(this.verterParameters.getSIGNER_URI()))
            {
                XmlSignatureHandler xs = new XmlSignatureHandler(this.verterParameters);
                xs.loadDocument(request.getInputStream());
                xs.sign();
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                //xs.output("c:\\UCELL\\data\\signed-nx2.xml");
                xs.outputHTTP(baos);
                VerterHttpClient sh = new VerterHttpClient(this.verterParameters);
                sh.sendHTTP(new ByteArrayInputStream (baos.toByteArray()));
            }
            if (target.toString().equals(this.verterParameters.getVALIDATOR_URI())) {
                SignValidate sv = new SignValidate(this.verterParameters);
               // sv.valSig("c:\\UCELL\\data\\signed-nx1.xml");
                sv.valSig(request.getInputStream());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        response.getWriter().println("OK");
        response.setContentType("text/html;charset=utf-8");
        response.setStatus(HttpServletResponse.SC_OK);
        baseRequest.setHandled(true);


    }
}