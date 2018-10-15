package thecollectiveweb.com.tcwhois;

import android.os.AsyncTask;
import android.util.Log;
import android.util.Patterns;

import org.apache.commons.net.whois.WhoisClient;

import java.io.IOException;
import java.net.SocketException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.ExecutionException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TCWHOIS {
    String Domainname;
    String TLD;
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

    public String getTCWHOIS(String Domain, String TLD) throws ExecutionException, InterruptedException {
        //for domains other than .com,.net,.edu
        this.Domainname = Domain;
        this.TLD = TLD;
        return new getwhoisTLD().execute().get();
    }

    public  class getwhois extends AsyncTask<String,Void,String> {



        @Override
        protected String doInBackground(String... strings) {
            return getWhois(Domainname,"com");
        }
    }

    public  class getwhoisTLD extends AsyncTask<String,Void,String> {



        @Override
        protected String doInBackground(String... strings) {
            return getWhois(Domainname,TLD);
        }
    }


    public String getWhois(String domainName) {

        StringBuilder result = new StringBuilder("");

        WhoisClient whois = new WhoisClient();
        try {



           whois.connect(WhoisClient.DEFAULT_HOST);

            //whois.connect("whois.iana.org");

            // whois =google.com
            String whoisData1 = whois.query("=" + domainName);
            Log.v("whoisreq",whoisData1);

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

    public String getWhois(String domainName , String TLD) {



        StringBuilder result = new StringBuilder("");

        WhoisClient whois = new WhoisClient();
        try {
            String whoisData1;
            //String [] TLDs= {"ac","ad","ae","aer","af","ag","ai","al","am","as","asi","at","au","aw","ax","az","ba","bar","be","ber","bes","bg","bi","biz","bj","bo","br","br.","bt","bw","by","bz","bzh","ca","cat","cc","cd","ceo","cf","ch","ci","ck","cl","clo","clu","cn","cn.","co","co.","com","coo","cx","cy","cz","de","dk","dm","dz","ec","edu","ee","eg","es","eu","eu.","eus","fi","fo","fr","gb","gb.","gb.","qc.","ge","gg","gi","gl","gm","gov","gr","gs","gy","ham","hip","hk","hm","hn","hos","hr","ht","hu","hu.","id","ie","il","im","in","inf","ing","ink","int","io","iq","ir","is","it","je","job","jp","ke","kg","ki","kr","kz","la","li","lon","lt","lu","lv","ly","ma","mc","md","me","mg","mil","mk","ml","mo","mob","ms","mt","mu","mus","mx","my","mz","na","nam","nc","net","nf","ng","nl","no","no.","nu","nz","om","ong","ooo","org","par","pe","pf","pic","pl","pm","pr","pre","pro","pt","pub","pw","qa","re","ro","rs","ru","sa","sa.","sb","sc","se","se.","se.","sg","sh","si","sk","sm","st","so","su","sx","sy","tc","tel","tf","th","tj","tk","tl","tm","tn","to","top","tp","tr","tra","tw","tv","tz","ua","ug","uk","uk.","uk.","ac.","gov","us","us.","uy","uy.","uz","va","vc","ve","vg","vu","wan","wf","wik","ws","xxx","xyz","yu","za"};
            //String [] Servers = {}
            switch (TLD) {
                case "com":
                    whois.connect(WhoisClient.DEFAULT_HOST);
                    whoisData1 = whois.query("=" + domainName);
                    break;
                case "in":

                    whois.connect("whois.inregistry.net");

                    whoisData1 = whois.query("" + domainName);
                    break;
                case "ac":

                    whois.connect("whois.nic.ac");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "ad":

                    whois.connect("whois.ripe.net");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "ae":

                    whois.connect("whois.aeda.net.ae");
                    //whois.connect("whois.nic.ae");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "aero":

                    whois.connect("whois.aero");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "af":

                    whois.connect("whois.nic.af");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "ag":

                    whois.connect("whois.nic.ag");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "ai":

                    whois.connect("whois.nic.ai");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "al":

                    whois.connect("whois.ripe.net");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "am":

                    whois.connect("whois.amnic.net");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "as":

                    whois.connect("whois.nic.as");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "asia":

                    whois.connect("whois.nic.asia");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "at":

                    whois.connect("whois.nic.at");
                    whoisData1 = whois.query("" + domainName);
                    break;

                case "au":

                    whois.connect("whois.aunic.net");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "aw":

                    whois.connect("whois.nic.aw");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "ax":

                    whois.connect("whois.ax");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "az":

                    whois.connect("whois.ripe.net");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "ba":

                    whois.connect("whois.ripe.net");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "bar":

                    whois.connect("whois.nic.bar");
                    whoisData1 = whois.query("" + domainName);
                    break;


                case "be":

                    whois.connect("whois.dns.be");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "berlin":

                    whois.connect("whois.nic.berlin");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "best":

                    whois.connect("whois.nic.best");
                    //whois.connect("whois.nic.ae");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "bg":

                    whois.connect("whois.register.bg");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "bi":

                    whois.connect("whois.nic.bi");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "biz":

                    whois.connect("whois.neulevel.biz");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "bj":

                    whois.connect("whois.nic.bj"); //could be www.nic.bj
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "bo":

                    whois.connect("whois.nic.bo");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "br":

                    whois.connect("whois.nic.br");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "br.com":

                    whois.connect("whois.centralnic.com");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "bt":

                    whois.connect("whois.netnames.net");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "bw":

                    whois.connect("whois.nic.net.bw");
                    whoisData1 = whois.query("" + domainName);
                    break;

                case "by":

                    whois.connect("whois.cctld.by");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "bz":

                    whois.connect("whois.belizenic.bz");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "bzh":

                    whois.connect("whois-bzh.nic.fr");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "ca":

                    whois.connect("whois.cira.ca");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "cat":

                    whois.connect("whois.cat");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "cc":

                    whois.connect("whois.nic.cc");
                    whoisData1 = whois.query("" + domainName);
                    break;


                case "cd":

                    whois.connect("whois.nic.cd");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "ceo":

                    whois.connect("whois.nic.ceo");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "cf":

                    whois.connect("whois.dot.cf");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "ch":

                    whois.connect("whois.nic.ch");
                    //whois.connect("whois.nic.ae");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "ci":

                    whois.connect("whois.nic.ci");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "ck":

                    whois.connect("whois.nic.ck");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "cl":

                    whois.connect("whois.nic.cl");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "cloud":

                    whois.connect("whois.nic.cloud");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "club":

                    whois.connect("whois.nic.club");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "cn":

                    whois.connect("whois.cnnic.net.cn");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "cn.com":

                    whois.connect("whois.centralnic.com");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "co":

                    whois.connect("whois.nic.co");
                    whoisData1 = whois.query("" + domainName);
                    break;

                case "co.nl":

                    whois.connect("whois.co.nl");
                    whoisData1 = whois.query("" + domainName);
                    break;

                case "coop":

                    whois.connect("whois.nic.coop");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "cx":

                    whois.connect("whois.nic.cx");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "cy":

                    whois.connect("whois.ripe.net");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "cz":

                    whois.connect("whois.nic.cz");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "de":

                    whois.connect("whois.denic.de");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "dk":

                    whois.connect("whois.dk-hostmaster.dk");
                    whoisData1 = whois.query("" + domainName);
                    break;

                case "dm":

                    whois.connect("whois.nic.cx");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "dz":

                    whois.connect("whois.nic.dz");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "ec":

                    whois.connect("whois.nic.ec");
                    //whois.connect("whois.nic.ae");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "edu":

                    whois.connect("whois.educause.net");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "ee":

                    whois.connect("whois.tld.ee");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "eg":

                    whois.connect("whois.ripe.net");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "es":

                    whois.connect("whois.nic.es"); //could be www.nic.bj
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "eu":

                    whois.connect("whois.nic.bo");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "eu.com":

                    whois.connect("whois.centralnic.com");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "eus":

                    whois.connect("whois.nic.eus");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "fi":

                    whois.connect("whois.fi");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "fo":

                    whois.connect("whois.nic.fo");
                    whoisData1 = whois.query("" + domainName);
                    break;

                case "fr":

                    whois.connect("whois.nic.fr");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "gb":

                    whois.connect("whois.ripe.net");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "gb.com":

                    whois.connect("whois.centralnic.com");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "gb.net":

                    whois.connect("whois.centralnic.com");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "qc.com":

                    whois.connect("whois.centralnic.com");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "ge":

                    whois.connect("whois.ripe.net");
                    whoisData1 = whois.query("" + domainName);
                    break;


                case "gg":

                    whois.connect("whois.gg");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "gi":

                    whois.connect("whois2.afilias-grs.net");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "gl":

                    whois.connect("whois.nic.gl");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "gm":

                    whois.connect("whois.ripe.net");
                    //whois.connect("whois.nic.ae");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "gov":

                    whois.connect("whois.nic.gov");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "gr":

                    whois.connect("whois.ripe.net");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "gs":

                    whois.connect("whois.nic.gs");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "gy":

                    whois.connect("whois.registry.gy");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "hamburg":

                    whois.connect("whois.nic.hamburg");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "hiphop":

                    whois.connect("whois.uniregistry.net");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "hk":

                    whois.connect("whois.hknic.net.hk");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "hm":

                    whois.connect("whois.registry.hm");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "hn":

                    whois.connect("whois2.afilias-grs.net");
                    whoisData1 = whois.query("" + domainName);
                    break;

                case "host":

                    whois.connect("whois.nic.host");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "hr":

                    whois.connect("whois.dns.hr");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "ht":

                    whois.connect("whois.nic.ht");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "hu":

                    whois.connect("whois.nic.hu");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "hu.com":

                    whois.connect("whois.centralnic.com");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "id":

                    whois.connect("whois.pandi.or.id");
                    whoisData1 = whois.query("" + domainName);
                    break;


                case "ie":

                    whois.connect("whois.domainregistry.ie");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "il":

                    whois.connect("whois.isoc.org.il");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "im":

                    whois.connect("whois.nic.im");
                    //whois.connect("whois.nic.ae");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "info":

                    whois.connect("whois.afilias.info");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "ing":

                    whois.connect("domain-registry-whois.l.google.com");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "ink":

                    whois.connect("whois.centralnic.com");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "int":

                    whois.connect("whois.isi.edu");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "io":

                    whois.connect("whois.nic.io");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "iq":

                    whois.connect("whois.cmc.iq");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "ir":

                    whois.connect("whois.nic.ir");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "is":

                    whois.connect("whois.isnic.is");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "it":

                    whois.connect("whois.nic.it");
                    whoisData1 = whois.query("" + domainName);
                    break;

                case "je":

                    whois.connect("whois.je");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "jobs":

                    whois.connect("obswhois.verisign-grs.com");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "jp":

                    whois.connect("whois.jprs.jp");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "ke":

                    whois.connect("whois.kenic.or.ke");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "kg":

                    whois.connect("whois.domain.kg");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "ki":

                    whois.connect("whois.nic.ki");
                    whoisData1 = whois.query("" + domainName);
                    break;


                case "kr":

                    whois.connect("whois.kr");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "kz":

                    whois.connect("whois.nic.kz");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "la":

                    whois.connect("whois2.afilias-grs.net");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "li":

                    whois.connect("whois.nic.li");
                    //whois.connect("whois.nic.ae");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "london":

                    whois.connect("whois.nic.london");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "lt":

                    whois.connect("whois.domreg.lt");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "lu":

                    whois.connect("whois.restena.lu");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "lv":

                    whois.connect("whois.nic.lv");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "ly":

                    whois.connect("whois.lydomains.com");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "ma":

                    whois.connect("whois.iam.net.ma");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "mc":

                    whois.connect("whois.ripe.net");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "md":

                    whois.connect("whois.nic.md");
                    whoisData1 = whois.query("" + domainName);
                    break;

                case "me":

                    whois.connect("whois.nic.me");
                    whoisData1 = whois.query("" + domainName);
                    break;

                case "mg":

                    whois.connect("whois.nic.mg");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "mil":

                    whois.connect("whois.nic.mil");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "mk":

                    whois.connect("whois.ripe.net");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "ml":

                    whois.connect("whois.dot.ml");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "mo":

                    whois.connect("whois.monic.mo");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "mobi":

                    whois.connect("whois.dotmobiregistry.net");
                    whoisData1 = whois.query("" + domainName);
                    break;

                case "ms":

                    whois.connect("whois.nic.ms");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "mt":

                    whois.connect("whois.ripe.net");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "mu":

                    whois.connect("whois.nic.mu");
                    //whois.connect("whois.nic.ae");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "museum":

                    whois.connect("whois.museum");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "mx":

                    whois.connect("whois.nic.mx");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "my":

                    whois.connect("whois.mynic.net.my");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "mz":

                    whois.connect("whois.nic.mz");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "na":

                    whois.connect("whois.na-nic.com.na");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "name":

                    whois.connect("whois.nic.name");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "nc":

                    whois.connect("whois.nc");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "net":

                    whois.connect("whois.verisign-grs.com");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "nf":

                    whois.connect("whois.nic.nf");
                    whoisData1 = whois.query("" + domainName);
                    break;

                case "ng":

                    whois.connect("whois.nic.net.ng");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "nl":

                    whois.connect("whois.domain-registry.nl");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "no":

                    whois.connect("whois.norid.no");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "no.com":

                    whois.connect("whois.centralnic.com");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "nu":

                    whois.connect("whois.nic.nu");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "nz":

                    whois.connect("whois.srs.net.nz");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "om":

                    whois.connect("whois.registry.om");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "ong":

                    whois.connect("whois.publicinterestregistry.net");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "ooo":

                    whois.connect("whois.nic.ooo");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "org":

                    whois.connect("whois.pir.org");
                    //whois.connect("whois.nic.ae");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "paris":

                    whois.connect("whois-paris.nic.fr");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "pe":

                    whois.connect("kero.yachay.pe");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "pf":

                    whois.connect("whois.registry.pf");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "pics":

                    whois.connect("whois.uniregistry.net");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "pl":

                    whois.connect("whois.dns.pl");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "pm":

                    whois.connect("whois.nic.pm");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "pr":

                    whois.connect("whois.nic.pr");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "press":

                    whois.connect("whois.nic.press");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "pro":

                    whois.connect("whois.registrypro.pro");
                    whoisData1 = whois.query("" + domainName);
                    break;

                case "pt":

                    whois.connect("whois.dns.pt");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "pub":

                    whois.connect("whois.unitedtld.com");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "pw":

                    whois.connect("whois.nic.pw");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "qa":

                    whois.connect("whois.registry.qa");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "re":

                    whois.connect("whois.nic.re");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "ro":

                    whois.connect("whois.rotld.ro");
                    whoisData1 = whois.query("" + domainName);
                    break;


                case "rs":

                    whois.connect("whois.rnids.rs");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "ru":

                    whois.connect("whois.tcinet.ru");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "sa":

                    whois.connect("saudinic.net.sa");
                    //whois.connect("whois.nic.ae");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "sa.com":

                    whois.connect("whois.centralnic.com");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "sb":

                    whois.connect("whois.nic.net.sb");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "sc":

                    whois.connect("whois2.afilias-grs.net");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "se":

                    whois.connect("whois.nic-se.se"); //could be www.nic.bj
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "se.com":

                    whois.connect("whois.centralnic.com");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "se.net":

                    whois.connect("whois.centralnic.com");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "sg":

                    whois.connect("whois.nic.net.sg");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "sh":

                    whois.connect("whois.nic.sh");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "si":

                    whois.connect("whois.arnes.si");
                    whoisData1 = whois.query("" + domainName);
                    break;

                case "sk":

                    whois.connect("whois.sk-nic.sk");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "sm":

                    whois.connect("whois.nic.sm");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "st":

                    whois.connect("whois.nic.st");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "so":

                    whois.connect("whois.nic.so");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "su":

                    whois.connect("whois.tcinet.ru");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "sx":

                    whois.connect("whois.sx");
                    whoisData1 = whois.query("" + domainName);
                    break;


                case "sy":

                    whois.connect("whois.tld.sy");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "tc":

                    whois.connect("whois.adamsnames.tc");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "tel":

                    whois.connect("whois.nic.tel");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "tf":

                    whois.connect("whois.nic.tf");
                    //whois.connect("whois.nic.ae");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "th":

                    whois.connect("whois.thnic.net");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "tj":

                    whois.connect("whois.nic.tj");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "tk":

                    whois.connect("whois.nic.tk");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "tl":

                    whois.connect("whois.domains.tl");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "tm":

                    whois.connect("whois.nic.tm");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "tn":

                    whois.connect("whois.ati.tn");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "to":

                    whois.connect("whois.tonic.to");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "top":

                    whois.connect("whois.nic.top");
                    whoisData1 = whois.query("" + domainName);
                    break;

                case "tp":

                    whois.connect("whois.domains.tl");
                    whoisData1 = whois.query("" + domainName);
                    break;

                case "tr":

                    whois.connect("whois.nic.tr");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "travel":

                    whois.connect("whois.nic.travel");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "tw":

                    whois.connect("whois.twnic.net.tw");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "tv":

                    whois.connect("whois.nic.tv");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "tz":

                    whois.connect("whois.tznic.or.tz");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "ua":

                    whois.connect("whois.ua");
                    whoisData1 = whois.query("" + domainName);
                    break;

                case "ug":

                    whois.connect("whois.co.ug");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "uk":

                    whois.connect("whois.nic.uk");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "uk.com":

                    whois.connect("whois.centralnic.com");
                    //whois.connect("whois.nic.ae");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "uk.net":

                    whois.connect("whois.centralnic.com");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "ac.uk":

                    whois.connect("whois.ja.net");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "gov.uk":

                    whois.connect("whois.ja.net");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "us":

                    whois.connect("whois.nic.us"); //could be www.nic.bj
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "us.com":

                    whois.connect("whois.centralnic.com");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "uy":

                    whois.connect("nic.uy");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "uy.com":

                    whois.connect("whois.centralnic.com");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "uz":

                    whois.connect("whois.cctld.uz");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "va":

                    whois.connect("whois.ripe.net");
                    whoisData1 = whois.query("" + domainName);
                    break;

                case "vc":

                    whois.connect("whois2.afilias-grs.net");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "ve":

                    whois.connect("whois.nic.ve");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "vg":

                    whois.connect("ccwhois.ksregistry.net");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "vu":

                    whois.connect("vunic.vu");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "wang":

                    whois.connect("whois.nic.wang");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "wf":

                    whois.connect("whois.nic.wf");
                    whoisData1 = whois.query("" + domainName);
                    break;


                case "wiki":

                    whois.connect("whois.nic.wiki");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "ws":

                    whois.connect("whois.website.ws");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "xxx":

                    whois.connect("whois.nic.xxx");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "xyz":

                    whois.connect("whois.nic.xyz");
                    //whois.connect("whois.nic.ae");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "yu":

                    whois.connect("whois.ripe.net");
                    whoisData1 = whois.query("" + domainName);
                    break;
                case "za.com":

                    whois.connect("whois.centralnic.com");
                    whoisData1 = whois.query("" + domainName);
                    break;


                default:

                    whois.connect(WhoisClient.DEFAULT_HOST);
                    whoisData1 = whois.query("=" + domainName);
                    break;
            }





            //whois.connect("whois.iana.org");

            // whois =google.com


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

    public String getRegistryDomainID(String Domainname)throws ExecutionException, InterruptedException {
        this.Domainname = Domainname;
        String whois = new getwhois().execute().get();
        if (!whois.contains("No match for")){

        String [] rawdata = whois.split("\n");
        String []rd = rawdata[1].split(": ");
        return rd[1];
        }
        else {
            return "Domain not Found\n\n\nThe Registry database contains ONLY .COM, .NET, .EDU domains and Registrars.";
        }
        //return rawdata[1];
    }

    public String getRegistrarURL(String Domainname)throws ExecutionException, InterruptedException {

        this.Domainname = Domainname;
        String whois = new getwhois().execute().get();
        if (!whois.contains("No match for")){
        String [] rawdata = whois.split("\n");
        String []rd = rawdata[3].split(": ");
        return rd[1];}
        else {
            return "Domain not Found\n\n\nThe Registry database contains ONLY .COM, .NET, .EDU domains and Registrars.";
        }
        //return rawdata[1];
    }

    public String getUpdatedateRAW(String Domainname)throws ExecutionException, InterruptedException {
        this.Domainname = Domainname;
        String whois = new getwhois().execute().get();
        if (!whois.contains("No match for")){
        String [] rawdata = whois.split("\n");
        String []rd = rawdata[4].split(": ");
        return rd[1];}
        else {
            return "Domain not Found\n\n\nThe Registry database contains ONLY .COM, .NET, .EDU domains and Registrars.";
        }
    }

    public String getUpdatedayFORMATED(String Domainname)throws ExecutionException, InterruptedException {
        String DATE = "Error in Parsing";
        String TIME = "Error in Parsing";
        this.Domainname = Domainname;
        String whois = new getwhois().execute().get();
        if (!whois.contains("No match for")) {
            String[] rawdata = whois.split("\n");
            String[] rd = rawdata[4].split(": ");
            String date = rd[1];
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
            try {
                Date date1 = sdf.parse(date);
                sdf.applyPattern("dd:MM:yyyy HH:mm:ss");
                DATE = sdf.format(date1);
            } catch (Exception ex) { // here forgot the exact exception class Parse exception was used
                // do something here
            }
            return DATE;
        }
        else {
            return "Domain not Found\n\n\nThe Registry database contains ONLY .COM, .NET, .EDU domains and Registrars.";
        }
    }

    public String getCreationdateRAW(String Domainname)throws ExecutionException, InterruptedException {
        this.Domainname = Domainname;
        String whois = new getwhois().execute().get();
        if (!whois.contains("No match for")) {
        String [] rawdata = whois.split("\n");
        String []rd = rawdata[5].split(": ");
        return rd[1];}
        else {
            return "Domain not Found\n\n\nThe Registry database contains ONLY .COM, .NET, .EDU domains and Registrars.";
        }
    }

    public String getCreationdayFORMATED(String Domainname)throws ExecutionException, InterruptedException {
        String DATE = "Error in Parsing";
        String TIME = "Error in Parsing";
        this.Domainname = Domainname;
        String whois = new getwhois().execute().get();
        String [] rawdata = whois.split("\n");
        String []rd = rawdata[5].split(": ");
        String date =  rd[1];
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        try{
            Date date1 = sdf.parse(date);
            sdf.applyPattern("dd:MM:yyyy HH:mm:ss");
            DATE = sdf.format(date1);
        }catch(Exception ex) { // here forgot the exact exception class Parse exception was used
            // do something here
        }
        return DATE;
    }

    public String getRegistryDomainID()throws ExecutionException, InterruptedException {
        //this.Domainname = Domainname;
        String whois = new getwhois().execute().get();
        String [] rawdata = whois.split("\n");
        String []rd = rawdata[1].split(": ");
        return rd[1];
    }
}
