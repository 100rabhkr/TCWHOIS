package thecollectiveweb.com.domaincheck;

import android.os.AsyncTask;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Patterns;
import android.view.KeyEvent;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.RelativeLayout;
import android.widget.TextView;

import org.apache.commons.net.whois.WhoisClient;

import java.io.IOException;
import java.net.SocketException;
import java.util.concurrent.ExecutionException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import thecollectiveweb.com.tcwhois.TCWHOIS;

public class MainActivity extends AppCompatActivity {

    private static Pattern pattern;
    private Matcher matcher;

    // regex whois parser
    private static final String WHOIS_SERVER_PATTERN = "Whois Server:\\s(.*)";

    static {
        pattern = Pattern.compile(WHOIS_SERVER_PATTERN);
    }
    RelativeLayout par;
    ProgressBar progressBar;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        //String whois = getWhois("google.com");

        par = findViewById(R.id.parent);
        textView = new TextView(getApplicationContext());
        par.addView(textView);

        final EditText editText = findViewById(R.id.dmn);
        editText.setOnKeyListener(new View.OnKeyListener() {

            @Override
            public boolean onKey(View view, int i, KeyEvent keyEvent) {
                if ((keyEvent.getAction() == KeyEvent.ACTION_DOWN) &&
                        (i == KeyEvent.KEYCODE_ENTER)) {
                    // Perform action on key press
                    //Toast.makeText(HelloFormStuff.this, edittext.getText(), Toast.LENGTH_SHORT).show();
                    if (editText.getText().toString().equals("")){
                        editText.setError("This field can't be empty");
                    }
                    else {

                        Domainname = editText.getText().toString();
                        // if
                        new getwhois().execute();
                    }



                return true;
                }
                return false;
            }

        });
        Button run = findViewById(R.id.run);
        Button clear = findViewById(R.id.clear);
        clear.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                editText.setText("");
                editText.setHint("ex: google.com");
                textView.setText("");
                Domainname = "";
            }
        });

        run.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if (editText.getText().toString().equals("")){
                    editText.setError("This field can't be empty");
                }
                else {

                    Domainname = editText.getText().toString();
                   // if
                    //new getwhois().execute();
                    TCWHOIS ff = new TCWHOIS();
                    try {
                        String strings = ff.getTCWHOIS(Domainname);
                        textView.setText(strings);
                    } catch (ExecutionException e) {
                        e.printStackTrace();
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            }

        });


    }

    String Domainname;

    // example google.com
    TextView textView;

    public  class getwhois extends AsyncTask<String,Void,String>{

        @Override
        protected void onPostExecute(String s) {
           // super.onPostExecute(s);
//progressBar.setVisibility(View.GONE);
            textView.setText(s);


        }

        @Override
        protected String doInBackground(String... strings) {
            return getWhois(Domainname);
        }

        @Override
        protected void onPreExecute() {
            //super.onPreExecute();
            //progressBar.setVisibility(View.VISIBLE);
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
