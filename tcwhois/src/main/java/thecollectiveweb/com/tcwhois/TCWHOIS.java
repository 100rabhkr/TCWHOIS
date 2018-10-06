package thecollectiveweb.com.tcwhois;

import android.os.AsyncTask;
import android.util.Patterns;

import org.apache.commons.net.whois.WhoisClient;

import java.io.IOException;
import java.net.SocketException;
import java.util.concurrent.ExecutionException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TCWHOIS {
    String Domainname;
    private static Pattern pattern;
    private Matcher matcher;

    // regex whois parser
    private static final String WHOIS_SERVER_PATTERN = "Whois Server:\\s(.*)";

    static {
        pattern = Pattern.compile(WHOIS_SERVER_PATTERN);
    }

    public void setDomain(String Domain){
        this.Domainname = Domain;
    }

    public String getTCWHOIS(String Domain) throws ExecutionException, InterruptedException {
        this.Domainname = Domain;
        return new getwhois().execute().get();
    }

    public  class getwhois extends AsyncTask<String,Void,String> {



        @Override
        protected String doInBackground(String... strings) {
            return getWhois(Domainname);
        }
    }


    public String getWhois(String domainName) {

        StringBuilder result = new StringBuilder("");

        WhoisClient whois = new WhoisClient();
        try {

            whois.connect(WhoisClient.DEFAULT_HOST);

            // whois =google.com
            String whoisData1 = whois.query("=" + domainName);

            // append first result
            result.append(whoisData1);
            whois.disconnect();

            // get the google.com whois server - whois.markmonitor.com
            String whoisServerUrl = getWhoisServer(whoisData1);
            if (!whoisServerUrl.equals("")) {

                // whois -h whois.markmonitor.com google.com
                String whoisData2 =
                        queryWithWhoisServer(domainName, whoisServerUrl);

                // append 2nd result
                result.append(whoisData2);
            }

        } catch (SocketException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return result.toString();

    }

    private String queryWithWhoisServer(String domainName, String whoisServer) {

        String result = "";
        WhoisClient whois = new WhoisClient();
        try {

            whois.connect(whoisServer);
            result = whois.query(domainName);
            whois.disconnect();

        } catch (SocketException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return result;

    }

    private String getWhoisServer(String whois) {

        String result = "";

        matcher = pattern.matcher(whois);

        // get last whois server
        while (matcher.find()) {
            result = matcher.group(1);
        }
        return result;
    }


    private boolean isValidUrl(String url) {
        Pattern p = Patterns.WEB_URL;
        Matcher m = p.matcher(url.toLowerCase());
        return m.matches();
    }

}
