.. _example_codes1:

Клиент жишээ кодууд
====================

1. Python хэл дээрх хэрэгжүүлэлт
----------------------------------

	| 1.1 Шаардлагатай “package”-уудыг суулгах

	.. code-block:: bash

		$ cat requirements.txt
		appdirs==1.4.3
		cached-property==1.3.1
		certifi==2017.7.27.1
		chardet==3.0.4
		defusedxml==0.5.0
		idna==2.6
		isodate==0.6.0
		lxml==4.1.1
		pytz==2017.3
		requests==2.18.4
		requests-toolbelt==0.8.0
		six==1.11.0
		urllib3==1.22
		zeep==2.4.0
		pycrypto==2.6.1

		$ pip install -r requirements.txt

	|	1.2 Тоон гарын үсэг зурах модуль “XypSign.py”

	.. code-block:: python

		import os
		import time
		from base64 import b64encode
		from Crypto.Hash import SHA256
		from Crypto.Signature import PKCS1_v1_5
		from Crypto.PublicKey import RSA

		class XypSign:

		def __init__(self, KeyPath):
		    self.KeyPath = KeyPath

		def __GetPrivKey(self):
		    with open(self.KeyPath, "rb") as keyfile:
		    return RSA.importKey(keyfile.read())

		def __toBeSigned(self, accessToken):
		    return {
		    'accessToken' : accessToken,
		    'timeStamp' : self.__timestamp(),
		    }

		def __buildParam(self, toBeSigned):
		    return toBeSigned['accessToken'] + '.' + toBeSigned['timeStamp']

		def sign(self, accessToken):
		    toBeSigned = self.__toBeSigned(accessToken)
		    digest = SHA256.new()
		    digest.update( self.__buildParam(toBeSigned) )
		    pkey = self.__GetPrivKey()
		    return toBeSigned, b64encode(PKCS1_v1_5.new(pkey).sign(digest))

		def __timestamp(self):
		    return str(int(time.time()))

		if __name__ == '__main__':

		ds = XypSign('prvate_key.key')
		toBeSigned, signature = ds.sign('access_token')

		print toBeSigned
		print signature		

	| 1.3 ХУР Төрийн Мэдээлэл Солилцооны системээс сервис дуудах жишээ код “XypClient.py”

	.. code-block:: python

		# -*- coding: utf-8 -*-
		import zeep, base64
		from XypSign import XypSign
		from requests import Session

		class Service():

		def __init__(self, wsdl, pkey_path=None):
		    """
		    param: wsdl - wsdl зам
		    param: pkey_path - VPN сүлжээнд холбогдоход өгсөн хувийн түлхүүрийн файлын зам.
		    """
		    self.__accessToken = 'access_token'
		    self.__toBeSigned, self.__signature = XypSign(pkey_path).sign(self.__accessToken)

		    session = Session()
		    session.verify = False
		    transport = zeep.Transport(session=session)

		    self.client = zeep.Client(wsdl, transport=transport)
		    self.client.transport.session.headers.update({
		    'accessToken': self.__accessToken,
		    'timeStamp' : self.__toBeSigned['timeStamp'],
		    'signature' : self.__signature
		    })

		def dump(self, operation, params):
		    try:
		    print self.client.service[operation](params)
		    except Exception, ex:
		    print operation, str(ex)

		params = {
		'auth': {
		    'citizen': {
		    'regnum': '',           # Иргэний регистрийн дугаар
		    'fingerprint': ''       # Иргэний хурууны хээний зураг. 310x310 харьцаатай PNG өртгөлтэй
		    },
		    'operator': {
		    'regnum': '',           # Үйлчилгээг үзүүлэгч ажилтны регистрийн дугаар
		    'fingerprint': ''       # Үйлчилгээг үзүүлэгч ажилтны хурууны хээний зураг. 310x310 харьцаатай PNG өртгөлтэй
		    }
		},
		'regnum' : ''               # Иргэний регистрийн дугаар
		}

		citizen = Service('https://xyp.gov.mn/citizen-1.2.1/ws?WSDL', pkey_path='private_key.key')
		citizen.dump('WS100101_getCitizenIDCardInfo', params)	

2. PHP хэл дээрх хэрэгжүүлэлт
-------------------------------

	| 2.1 Тоон гарын үсэг зурах модуль “XypSign.php”

	.. code-block:: php

		class XypSign{

		private $KeyPath;
		private $accessToken;

		function __construct($KeyPath, $accessToken){
		    $this->KeyPath = $KeyPath;
		    $this->accessToken = $accessToken;
		}

		public function sign(){
		    $pkey = file_get_contents($this->KeyPath);
		    $timestamp = time();
		    openssl_sign($this->accessToken . "." . $timestamp, $signature, $pkey, OPENSSL_ALGO_SHA256);
		    return [
		    'accessToken' => $this->accessToken,
		    'timeStamp' => $timestamp,
		    'signature' => base64_encode($signature),
		    ];
		}

		}

	|	2.2 ХУР Төрийн Мэдээлэл Солилцооны системээс сервис дуудах жишээ код “XypClient.php”

	.. code-block:: php

		require_once('XypSign.php');

		$keyPath = 'private_key.key';                       // VPN сүлжээнд холбогдоход өгсөн хувийн түлхүүрийн файлын зам.
		$accessToken = "access_token";                      // Хандалтын токен

		$sign = new XypSign($keyPath, $accessToken);
		$signingInfo = $sign->sign();

		try{
		$client = new SoapClient(
		    "https://xyp.gov.mn/citizen-1.2.1/ws?WSDL",
		    [
		    'soapVersion' => SOAP_1_2,
		    'stream_context' => stream_context_create([
		        'ssl' => [
		        'verify_peer' => false,
		        'allow_self_signed' => true
		        ],
		        'http' => [
		        'header' => "accessToken: $signingInfo[accessToken]\r\n".
		        "timeStamp: $signingInfo[timeStamp]\r\n".
		        "signature: $signingInfo[signature]"
		        ]
		    ])
		    ]
		);

		$soapParam = [
		    "auth" => [
		    "citizen" => [
		        "fingerprint" => "",       // Иргэний хурууны хээний зураг. 310x310 харьцаатай PNG өртгөлтэй
		        "regnum" => ""             // Иргэний регистрийн дугаар
		    ],
		    "operator" => [
		        "regnum" => "",            // Үйлчилгээг үзүүлэгч ажилтны регистрийн дугаар
		        "fingerprint" => ""        // Үйлчилгээг үзүүлэгч ажилтны хурууны хээний зураг. 310x310 харьцаатай PNG өртгөлтэй
		    ],
		    ],
		    "regnum" => ""                 // Иргэний регистрийн дугаар
		];

		$result = $client->WS100101_getCitizenIDCardInfo(['request' => $soapParam]);
		var_dump($result);

		}catch (\Exception $ex) {
		$result = "ХУР -тай холбогдох үд гарсан алдаа: " . $ex->getMessage();
		}

3. JAVA хэл дээрх хэрэгжүүлэлт
-------------------------------

	| 3.1 JKS файл үүсгэх Эхлээд VPN сүлжээнд холбогдоход өгөгдсөн тоон гэрчилгээ болон хувийн түлхүүрийг pkcs12 форматтай болгох ёстой.

	.. code-block:: bash

		$ openssl pkcs12 -export -in <certificate_file> -inkey "private_key_file" -name "xyp" -out <output_file.p12>
		Enter Export Password:
		Verifying - Enter Export Password:

		pkcs12 формат нь тоон гэрчилгээ хувийн түлхүүрийг нууц үгээр хамгаалдаг тул нууц үгийг заавал оруулж өгнө.

	| Java keytool ашиглан “JKS” файл үүсгэх.

	.. code-block:: bash

		$ keytool -importkeystore -deststorepass 'KEY_STORE_PASS' -destkeystore <jks_file_name.jks> -srckeystore <pkcs12_file.p12> -srcstoretype PKCS12
		Importing keystore <pkcs12_file.p12> to <jks_file_name.jks>...
		Enter source keystore password:
		Entry for alias xyp successfully imported.
		Import command completed:  1 entries successfully imported, 0 entries failed or cancelled

		KEY_STORE_PASS нь .p12 файлын нууц үгтэй ижилхэн байх ёстойг анхаарна уу... Ижилхэн биш бол JAVA - "Cannot recover key" Exception өгдөг.	

	|	3.2 xyp.gov.mn сайтын тоон гэрчилгээг JAVA итгэмжлэгдсэн гэрчилгээн санд нэмэх. Доорх InstallCert.java кодыг зааврын дагуу ажиллуулах.

	.. code-block:: java

		/*
		 * Copyright 2006 Sun Microsystems, Inc.  All Rights Reserved.
		 *
		 * Redistribution and use in source and binary forms, with or without
		 * modification, are permitted provided that the following conditions
		 * are met:
		 *
		 *   - Redistributions of source code must retain the above copyright
		 *     notice, this list of conditions and the following disclaimer.
		 *
		 *   - Redistributions in binary form must reproduce the above copyright
		 *     notice, this list of conditions and the following disclaimer in the
		 *     documentation and/or other materials provided with the distribution.
		 *
		 *   - Neither the name of Sun Microsystems nor the names of its
		 *     contributors may be used to endorse or promote products derived
		 *     from this software without specific prior written permission.
		 *
		 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
		 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
		 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
		 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
		 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
		 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
		 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
		 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
		 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
		 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
		 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
		 */
		/**
		 * Originally from:
		 * http://blogs.sun.com/andreas/resource/InstallCert.java
		 * Use:
		 * java InstallCert hostname
		 * Example:
		 *% java InstallCert ecc.fedora.redhat.com
		 */

		import javax.net.ssl.*;
		import java.io.*;
		import java.security.KeyStore;
		import java.security.MessageDigest;
		import java.security.cert.CertificateException;
		import java.security.cert.X509Certificate;

		public class InstallCert {

		    public static void main(String[] args) throws Exception {
		        String host;
		        int port;
		        char[] passphrase;
		        if ((args.length == 1) || (args.length == 2)) {
		            String[] c = args[0].split(":");
		            host = c[0];
		            port = (c.length == 1) ? 443 : Integer.parseInt(c[1]);
		            String p = (args.length == 1) ? "changeit" : args[1];
		            passphrase = p.toCharArray();
		        } else {
		            System.out.println("Usage: java InstallCert <host>[:port] [passphrase]");
		            return;
		        }

		        File file = new File("jssecacerts");
		        if (file.isFile() == false) {
		            char SEP = File.separatorChar;
		            File dir = new File(System.getProperty("java.home") + SEP
		                    + "lib" + SEP + "security");
		            file = new File(dir, "jssecacerts");
		            if (file.isFile() == false) {
		                file = new File(dir, "cacerts");
		            }
		        }
		        System.out.println("Loading KeyStore " + file + "...");
		        InputStream in = new FileInputStream(file);
		        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		        ks.load(in, passphrase);
		        in.close();

		        SSLContext context = SSLContext.getInstance("TLS");
		        TrustManagerFactory tmf =
		                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		        tmf.init(ks);
		        X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
		        SavingTrustManager tm = new SavingTrustManager(defaultTrustManager);
		        context.init(null, new TrustManager[]{tm}, null);
		        SSLSocketFactory factory = context.getSocketFactory();

		        System.out.println("Opening connection to " + host + ":" + port + "...");
		        SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
		        socket.setSoTimeout(10000);
		        try {
		            System.out.println("Starting SSL handshake...");
		            socket.startHandshake();
		            socket.close();
		            System.out.println();
		            System.out.println("No errors, certificate is already trusted");
		        } catch (SSLException e) {
		            System.out.println();
		            e.printStackTrace(System.out);
		        }

		        X509Certificate[] chain = tm.chain;
		        if (chain == null) {
		            System.out.println("Could not obtain server certificate chain");
		            return;
		        }

		        BufferedReader reader =
		                new BufferedReader(new InputStreamReader(System.in));

		        System.out.println();
		        System.out.println("Server sent " + chain.length + " certificate(s):");
		        System.out.println();
		        MessageDigest sha1 = MessageDigest.getInstance("SHA1");
		        MessageDigest md5 = MessageDigest.getInstance("MD5");
		        for (int i = 0; i < chain.length; i++) {
		            X509Certificate cert = chain[i];
		            System.out.println
		                    (" " + (i + 1) + " Subject " + cert.getSubjectDN());
		            System.out.println("   Issuer  " + cert.getIssuerDN());
		            sha1.update(cert.getEncoded());
		            System.out.println("   sha1    " + toHexString(sha1.digest()));
		            md5.update(cert.getEncoded());
		            System.out.println("   md5     " + toHexString(md5.digest()));
		            System.out.println();
		        }

		        System.out.println("Enter certificate to add to trusted keystore or 'q' to quit: [1]");
		        String line = reader.readLine().trim();
		        int k;
		        try {
		            k = (line.length() == 0) ? 0 : Integer.parseInt(line) - 1;
		        } catch (NumberFormatException e) {
		            System.out.println("KeyStore not changed");
		            return;
		        }

		        X509Certificate cert = chain[k];
		        String alias = host + "-" + (k + 1);
		        ks.setCertificateEntry(alias, cert);

		        OutputStream out = new FileOutputStream("cacerts");
		        ks.store(out, passphrase);
		        out.close();

		        System.out.println();
		        System.out.println(cert);
		        System.out.println();
		        System.out.println
		                ("Added certificate to keystore 'cacerts' using alias '"
		                        + alias + "'");
		    }

		    private static final char[] HEXDIGITS = "0123456789abcdef".toCharArray();

		    private static String toHexString(byte[] bytes) {
		        StringBuilder sb = new StringBuilder(bytes.length * 3);
		        for (int b : bytes) {
		            b &= 0xff;
		            sb.append(HEXDIGITS[b >> 4]);
		            sb.append(HEXDIGITS[b & 15]);
		            sb.append(' ');
		        }
		        return sb.toString();
		    }

		    private static class SavingTrustManager implements X509TrustManager {

		        private final X509TrustManager tm;
		        private X509Certificate[] chain;

		        SavingTrustManager(X509TrustManager tm) {
		            this.tm = tm;
		        }

		        public X509Certificate[] getAcceptedIssuers() {

		        /**
		         * This change has been done due to the following resolution advised for Java 1.7+
		        http://infposs.blogspot.kr/2013/06/installcert-and-java-7.html
		             **/

		        return new X509Certificate[0];
		            //throw new UnsupportedOperationException();
		        }

		        public void checkClientTrusted(X509Certificate[] chain, String authType)
		                throws CertificateException {
		            throw new UnsupportedOperationException();
		        }

		        public void checkServerTrusted(X509Certificate[] chain, String authType)
		                throws CertificateException {
		            this.chain = chain;
		            tm.checkServerTrusted(chain, authType);
		        }
		    }
		}


	.. code-block:: bash

		$ javac InstallCert.java
		$ java InstallCert xyp.gov.mn:443
		---------------------------------------------------------------
		Server sent 3 certificate(s):

		1 Subject CN=xyp.gov.mn, EMAILADDRESS=info@datacenter.gov.mn, O=National Data Center, OU=National Data Center, ST=Tuv, C=MN, L=Ulaanbaatar
		Issuer  CN=Mongolian National Issuing CA, O=ITPTA, OID.2.5.4.51="P.O.B-785, ITPTA Building", STREET="Chinggis Square -1, Chingeltei", L=Ulaanbaatar, C=MN
		sha1    1e 02 12 0d 1a 7f b0 3d 79 11 0d 3a 2a 36 84 af 3e 75 26 dd
		md5     94 81 3e 68 a8 45 15 a0 cf fa 9d e4 fc a3 c8 3b

		2 Subject CN=Mongolian National Root CA, O=ITPTA, C=MN
		Issuer  CN=Mongolian National Root CA, O=ITPTA, C=MN
		sha1    fe c5 53 5b 04 a9 09 7b b0 fb d0 e0 31 37 67 f8 57 d3 b4 6b
		md5     87 35 1c cb f4 23 1d 6f b6 26 fa c8 3b 3f c3 ac

		3 Subject CN=Mongolian National Issuing CA, O=ITPTA, OID.2.5.4.51="P.O.B-785, ITPTA Building", STREET="Chinggis Square -1, Chingeltei", L=Ulaanbaatar, C=MN
		Issuer  CN=Mongolian National Root CA, O=ITPTA, C=MN
		sha1    e6 a7 75 f9 2d 5e 32 dc 95 5f 3b 5c f7 44 df a0 fa 8b af 66
		md5     f7 20 ef 52 0b ad e5 7c 83 9a 59 65 5a 71 08 26

		Enter certificate to add to trusted keystore or 'q' to quit: [1]  # Enter дар.
		.........................................................
		.........................................................
		Added certificate to keystore 'cacerts' using alias 'xyp.gov.mn-1'

	| Үүссэн cacerts файлыг $JAVA_HOME/jre/lib/security хавтсанд хуулах. Хуулахаас өмнө cacerts файлыг нөөцлөж авна уу.

	| 3.3 “wsimport” түүлээр package үүсгэх

	.. code-block:: bash

		$ wsimport -d ./ https://xyp.gov.mn/citizen-1.2.1/ws?WSDL

	| Үүссэн “package”-ыг өөрийн прожектод импортлож оруулна.

	| 3.4 Тоон гарын үсэг зурах модуль “XypSign.java”

	.. code-block:: java

		import java.io.FileInputStream;
		import java.io.FileNotFoundException;
		import java.io.IOException;
		import java.util.Date;
		import java.util.Base64;
		import java.util.Hashtable;
		import java.text.DateFormat;
		import java.text.SimpleDateFormat;
		import java.security.InvalidKeyException;
		import java.security.KeyStore;
		import java.security.KeyStoreException;
		import java.security.NoSuchAlgorithmException;
		import java.security.PrivateKey;
		import java.security.Signature;
		import java.security.SignatureException;
		import java.security.UnrecoverableKeyException;
		import java.security.cert.CertificateException;

		public class XypSign {

		private final String instance = "JKS";
		private String password;
		private String aliasname;
		private String KeyPath;

		public XypSign(String KeyPath, String aliasname, String password){
		    this.KeyPath = KeyPath;
		    this.aliasname = aliasname;
		    this.password = password;
		}

		private String GetCurrentTimestamp(){
		    Date date = new Date();
		    DateFormat dtf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		        return Long.toString(date.getTime() / 1000);
		}

		private Hashtable<String, String> toBeSigned(String accessToken){
		    Hashtable<String, String> toBeSigned = new Hashtable<String, String>();
		    toBeSigned.put("accessToken", accessToken);
		    toBeSigned.put("timestamp", GetCurrentTimestamp());
		    return toBeSigned;
		}

		public Hashtable<String, String> Sign(String accessToken) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, UnrecoverableKeyException, InvalidKeyException, SignatureException{

		    String signature = null;

		    KeyStore KS = KeyStore.getInstance(instance);
		    KS.load(new FileInputStream(KeyPath), password.toCharArray());

		    PrivateKey pkey = (PrivateKey)KS.getKey(aliasname, password.toCharArray());
		    Hashtable<String, String> toBeSigned = toBeSigned(accessToken);

		    Signature ds = Signature.getInstance("SHA256withRSA");
		    ds.initSign(pkey);
		    ds.update( (toBeSigned.get("accessToken") + "." + toBeSigned.get("timestamp")).getBytes());
		    signature = Base64.getEncoder().encodeToString(ds.sign());

		    toBeSigned.put("signature", signature);

		    return toBeSigned;
		}
		}


	| 3.5 ХУР Төрийн Мэдээлэл Солилцооны системээс сервис дуудах жишээ код “XypClient.java”

	.. code-block:: java

		import com.ndc.external.citizen.*;

		import javax.xml.ws.BindingProvider;
		import javax.xml.ws.handler.MessageContext;
		import java.io.File;
		import java.io.FileInputStream;
		import java.io.IOException;
		import java.security.InvalidKeyException;
		import java.security.NoSuchAlgorithmException;
		import java.security.NoSuchProviderException;
		import java.security.SignatureException;
		import java.security.cert.CertificateException;
		import java.util.*;

		public class XypClient {

		static String wsdl = "https://xyp.gov.mn/citizen-1.2.1/ws?WSDL";
		static String accessToken = "access_token";
		static String aliasName = "xyp";
		static String keyPath = "JKS_file.jks";
		static String password = "JKS_PASSWORD";
		static String regNum = "";
		static byte[] imageData;                              // 310x310 харьцаатай PNG өртгөлтэй

		public static void main(String[] args) {

		    CitizenService citizenService = new CitizenServiceService().getCitizenServicePort();

		        Map<String, Object> req_ctx = ((BindingProvider)citizenService).getRequestContext();
		        req_ctx.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, wsdl);
		        Map<String, List<String>> headers = new HashMap<String, List<String>>();
		        Hashtable<String, String> fields = new XypSign(keyPath, aliasName, password).Sign(accessToken);

		        try{

		            headers.put("accessToken", Collections.singletonList(fields.get("accessToken")));
		            headers.put("timestamp", Collections.singletonList(fields.get("timestamp")));
		            headers.put("signature", Collections.singletonList(fields.get("signature")));
		            req_ctx.put(MessageContext.HTTP_REQUEST_HEADERS, headers);

		            CitizenRequestData requestData = new CitizenRequestData();
		            AuthorizationData authorizationData = new AuthorizationData();
		            AuthorizationEntity authorizationEntity = new AuthorizationEntity();

		            authorizationEntity.setRegnum(regNum);
		            authorizationEntity.setFingerprint(imageData);

		            authorizationData.setCitizen(authorizationEntity);

		            requestData.setRegnum(regNum);
		            requestData.setAuth(authorizationData);
		            ServiceResponse serviceResponse = citizenService.ws100101GetCitizenIDCardInfo(requestData);

		            System.out.println(serviceResponse.getResultCode());
		            System.out.println(serviceResponse.getResultMessage());

		        }catch(Exception e){
		            e.printStackTrace();
		            System.out.println(e.getMessage());
		            System.exit(1);
		        }
		}
		}	