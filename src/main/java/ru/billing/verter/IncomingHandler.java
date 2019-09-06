package ru.billing.verter;

import org.apache.commons.io.IOUtils;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public class IncomingHandler extends AbstractHandler
{

    VerterParameters verterParameters;
    IncomingHandler(VerterParameters iverterParameters) {
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
                xs.outputHTTP(baos);
                VerterHttpClient sh = new VerterHttpClient(this.verterParameters);
                InputStream is = sh.sendHTTP(new ByteArrayInputStream (baos.toByteArray()));

                response.getWriter().print(IOUtils.toString(is, StandardCharsets.UTF_8));
            }
            if (target.toString().equals(this.verterParameters.getVALIDATOR_URI())) {
                SignValidate sv = new SignValidate(this.verterParameters);
                sv.valSig(request.getInputStream(), response);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        response.setContentType("text/html;charset=utf-8");
        response.setStatus(HttpServletResponse.SC_OK);
        baseRequest.setHandled(true);


    }
}