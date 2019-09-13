package ru.billing.verter;

import org.apache.commons.io.IOUtils;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.slf4j.Logger;

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
    private Logger   logger;
    private String   logPrefix = "Incoming Handler: ";
    IncomingHandler(VerterParameters iverterParameters, Logger ilogger) {
        this.verterParameters = iverterParameters;
        this.logger = ilogger;
    }
    private void logInfoMessage (String msg) {logger.info(logPrefix+msg);}

    private void logDebugMessage (String msg) {logger.debug(logPrefix+msg);}

    public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException
    {
        try {
            if (target.toString().equals(this.verterParameters.getSIGNER_URI()))
            {

                XmlSignatureHandler xs = new XmlSignatureHandler(this.verterParameters,logger);
                xs.loadDocument(request.getInputStream());
                xs.sign();
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                xs.outputHTTP(baos);
                VerterHttpClient sh = new VerterHttpClient(this.verterParameters);
                InputStream is = sh.sendHTTP(new ByteArrayInputStream (baos.toByteArray()));

                response.getWriter().print(IOUtils.toString(is, StandardCharsets.UTF_8));
            }
            if (target.toString().equals(this.verterParameters.getVALIDATOR_URI())) {
                SignValidate sv = new SignValidate(this.verterParameters,logger);
                sv.valSig(request.getInputStream(), response);
            }
        } catch (Exception e) {
            logInfoMessage("HA HA HA. I have to go to the dump");
            logInfoMessage(e.getMessage());
            response.getWriter().println(e.getMessage());
        }
        response.setContentType("text/xml;charset=utf-8");
        response.setStatus(HttpServletResponse.SC_OK);
        baseRequest.setHandled(true);


    }
}