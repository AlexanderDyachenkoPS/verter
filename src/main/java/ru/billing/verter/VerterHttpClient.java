package ru.billing.verter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.entity.InputStreamEntity;
import org.apache.http.impl.client.DefaultHttpClient;
public class VerterHttpClient{

    VerterParameters verterParameters;

    public VerterHttpClient(VerterParameters iverterParameters) {
        this.verterParameters=iverterParameters;
    }

    public  InputStream sendHTTP(InputStream body4post) throws ClientProtocolException, IOException {
        HttpClient client = new DefaultHttpClient();
        HttpPost post = new HttpPost(this.verterParameters.getHLR_URI());
        InputStreamEntity input = new InputStreamEntity(body4post);
        post.setEntity(input);
        post.setHeader("Content-Type", "text/xml; charset=utf-8");
        post.setHeader("SOAPAction", "");

        HttpResponse response = client.execute(post);
        //BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
        return  response.getEntity().getContent();

    }
}