3. Гэрчилгээ нэмэх
===================

Хэрэглэгч нь өөрийн системд “Үндэсний суурь гэрчилгээ” болон “Үндэсний олгох гэрчилгээ” -г дараах зааврын дагуу суулгана.

3.1 “Root CA certificate”-д гэрчилгээ нэмэх
-------------------------------------------

**Дараах холбоосоор орж гэрчилгээг татаж авна.**
	|	Үндэсний суурь гэрчилгээ: https://esign.gov.mn/MNRCA.cer
	|	Үндэсний олгох гэрчилгээ: https://esign.gov.mn/MNICA-2018.cer

3.2 Cистемийн “Trusted root certificate”-д татаж авсан гэрчилгээнүүдийг суулгах
--------------------------------------------------------------------------------

	|	3.2.1 Mac OS X үйлдлийн систем дээрх тохиргоо
	|	**Terminal** нээж гэрчилгээ татаж авсан хавтас руу шилжсэний дараагаар дараах коммандыг бичнэ.

	.. code-block:: bash
		
		sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ./MNRCA.cer
   		sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ./MNICA.cer

	|	3.2.2 Windows үйлдлийн систем дээрх тохиргоо
	|	**Command promt** нээж гэрчилгээ татаж авсан хавтас руу шилжсэний дараагаар дараах коммандыг бичнэ:

	.. code-block:: bat

		certutil -addstore -f "ROOT" MNRCA.cer
		certutil -addstore -f "ROOT" MNICA.cer

	|	3.2.3 Linux үйлдлийн систем дээрх тохиргоо
	|	Таны системд ca-certificates package суусан байх шаардлагатай. Хэрэв суугаагүй бол дараах коммандыг **Terminal** дээр ажиллуулж суулгах боломжтой.

	.. code-block:: bash

		#Debian суурьтай үйлдлийн системтэй бол
		apt-get install ca-certificates
		#Redhat суурьтай системтэй бол
		yum install ca-certificates

	|	**Terminal** нээж гэрчилгээ татаж авсан хавтас руу шилжсэний дараагаар дараах коммандыг бичнэ.

	.. code-block:: bash

		#Debian суурьтай үйлдлийн системтэй бол
		sudo cp MNRCA.cer /usr/local/share/ca-certificates/
		sudo cp MNICA.cer /usr/local/share/ca-certificates/
		sudo update-ca-certificates
		#Redhat суурьтай үйлдлийн системтэй бол
		update-ca-trust force-enable
		cp MNRCA.cer /etc/pki/ca-trust/source/anchors/
		cp MNICA.cer /etc/pki/ca-trust/source/anchors/
		update-ca-trust extract

	|	3.2.4 Java хөгжүүлэлтийн орчинд “Trust Store”-т Root Certificate нэмэх
	|	Дараах коммандыг Windows орчинд бол **Command prompt**, Mac OS X болон Linux системтэй бол **Terminal** нээж гэрчилгээ татаж авсан хавтас руу шилжсэний дараагаар дээр дараах коммандыг бичнэ.

	.. code-block:: bash

		#JRE_HOME таны систем дэх JAVA суулгасан JRE_HOME хавтас Жишээ нь:
		/usr/java/<Java version jre> эсвэл C:/Java/<Java version jre> гэх мэт.
		JRE_HOME/bin/keytool -import  -trustcacerts -alias certAlias -file MNICA.cer -key store trustStoreFile
		#Гарч ирэх баталгаажуулах асуултанд **YES** гэсэн утгийг оруулан **"Enter"** товчийг дарна.