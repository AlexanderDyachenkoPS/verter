package ru.billing.verter;


import org.eclipse.jetty.server.Server;
import org.slf4j.LoggerFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class VerterMain  {

    Logger logger;

    public static void main(String[] argv) throws Exception {


        Logger logger =  LoggerFactory.getLogger("ru.billing.verter");

        logger.info("################################################################");
        logger.info("HA HA HA. I'm Verter. Alice , Where is the MIYELOPHONE?");
        logger.info("################################################################");

        final VerterParameters verterParameters= new VerterParameters(
                argv[0],       // iKEYFILE
                argv[1],       // iPRIVATE_KEY_ALIAS,
                argv[2],       // iPRIVATE_KEY_PASS,
                argv[3],       // iKEY_STORE_PASS,
                argv[4],       // iKEY_STORE_TYPE,
                argv[5],       // iLISTEN_PORT,
                argv[6],       // iVALIDATOR_URI,
                argv[7],       // iSIGNER_URI,
                argv[8],       // iHLR_URI
                logger
        );

       Integer serverPort = Integer.parseInt ( verterParameters.getLISTEN_PORT());
       Server server = new Server(serverPort);

        server.setHandler(new IncomingHandler(verterParameters, logger));

        logger.info("################################################################");
        logger.info("Starting...");
        logger.info("################################################################");

       server.start();
        server.join();

    }

}
