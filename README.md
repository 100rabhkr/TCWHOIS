<p><a href="https://android-arsenal.com/details/1/7176"><img src="https://img.shields.io/badge/Android%20Arsenal-TCWHOIS-blue.svg?style=flat" border="0" alt="Android Arsenal"></a> <a href="https://jitpack.io/#100rabhkr/TCWHOIS"><img src="https://jitpack.io/v/100rabhkr/TCWHOIS.svg" alt=""></a>   <a href="http://paypal.me/100rabhkr"><img src="https://img.shields.io/badge/Donate-PayPal-green.svg" alt="Donate"></a> <a href="http://github.com/badges/stability-badges"><img src="http://badges.github.io/stability-badges/dist/stable.svg" alt="stable"></a> </p> 

# TCWHOIS

A small library which allows you to check whois records of any domain registered on whois.


# Installation

To get a Git project into your build:

**Step 1.**  Add the JitPack repository to your build file

To get a Git project into your build:

**Step 1.**  Add the JitPack repository to your build file

Add it in your root build.gradle at the end of repositories:

```css
	allprojects {
		repositories {
			...
			maven { url 'https://jitpack.io' }
		}
	}
```

**Step 2.**  Add the dependency

```css
	dependencies {
	        implementation 'com.github.100rabhkr:TCWHOIS:v1.0'
	}
```

## Usage

The TCWHOIS has a very simple usage: 


   ```css
   
	TCWHOIS ff = new TCWHOIS();
    try {  
	    String strings = ff.getTCWHOIS(Domainname);  
	    textView.setText(strings);  
	} catch (ExecutionException e) {  
    e.printStackTrace();  
	} catch (InterruptedException e) {  
    e.printStackTrace();  
	}
```	

    

> **Note**
It can throw ExecutionException and InterruptedException so wrap it in a try-catch.
Also The syntax of the domain name should be domainname.suffix(GTLDs, example: .com, .edu, .net etc)
Currently the Registry database contains ONLY .COM, .NET, .EDU domains and Registrars. More TLDs are being added.
Example: google.com and not ~~www.~~ google.com
**No need to add www or any other subdomain**


## Demo

View the Demo [here](https://appetize.io/app/kmxxfkv3jxykb2z36fghtnc4z4?device=nexus5&scale=75&orientation=portrait&osVersion=7.1)

## Result

The TCWHOIS library returns result it string form.

**Sample Result**

    Domain Name: GOOGLE.COM  
	Registry Domain ID: 2138514_DOMAIN_COM-VRSN  
	Registrar WHOIS Server: whois.markmonitor.com  
	Registrar URL: http://www.markmonitor.com  
	Updated Date: 2018-02-21T18:36:40Z  
	Creation Date: 1997-09-15T04:00:00Z  
	Registry Expiry Date: 2020-09-14T04:00:00Z  
	Registrar: MarkMonitor Inc.  
	Registrar IANA ID: 292  
	Registrar Abuse Contact Email: abusecomplaints@markmonitor.com  
	Registrar Abuse Contact Phone: +1.2083895740  
	Domain Status: clientDeleteProhibited 		
	https://icann.org/epp#clientDeleteProhibited  
	Domain Status: clientTransferProhibited 
	https://icann.org/epp#clientTransferProhibited  
	Domain Status: clientUpdateProhibited 
	https://icann.org/epp#clientUpdateProhibited  
	Domain Status: serverDeleteProhibited 	
	https://icann.org/epp#serverDeleteProhibited  
	Domain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited  
	Domain Status: serverUpdateProhibited 	https://icann.org/epp#serverUpdateProhibited  
	Name Server: NS1.GOOGLE.COM  
	Name Server: NS2.GOOGLE.COM  
	Name Server: NS3.GOOGLE.COM  
	Name Server: NS4.GOOGLE.COM  
	DNSSEC: unsigned  
	URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/  

	For more information on Whois status codes, please visit https://icann.org/epp  
  
	NOTICE: The expiration date displayed in this record is the 	date the  
	registrar's sponsorship of the domain name registration in the registry is  
	currently set to expire. This date does not necessarily reflect the expiration  
	date of the domain name registrant's agreement with the sponsoring  
	registrar. Users may consult the sponsoring registrar's Whois database to  
	view the registrar's reported date of expiration for this registration.  
  


## Downloads

You can download the Library from [releases](https://github.com/100rabhkr/TCWHOIS/releases)



## Note

|![Managed](https://image.ibb.co/jiARgz/40978490_234042307291317_8497249025953628160_n.jpg)  | Created and Managed By |
|--|--|
| [@100rabhkr](https://github.com/100rabhkr) |For [The Collective Web](https://thecollectiveweb.com)  |
