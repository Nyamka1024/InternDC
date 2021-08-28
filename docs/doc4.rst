5. Вэб сервис дуудах
====================


.. note::Веб сервисийг дуудахдаа дараах зүйлүүдийг анхаарна уу.

|	**Олгогдсон accessToken -ийг HTTP Header утга дээр бичиж өгнө.**

Жишээ нь:

.. code-block:: xml

	accessToken: 391c3afec829361c1e3c92d22d89262c

|	**Веб сервисээр мэдээлэл солилцохдоо тодорхойлогдсон форматыг дагаж мөрдөнө.**

|	Веб сервист илгээх жишээ өгөгдлийн формат:

.. code-block:: xml

	<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
         <soap:Body>
            <ns2:WS100303_getLegalEntityLiqiudationInfoResponse xmlns:ns2="http://les.xyp. gov.mn/">
              <return>
                  <request xsi:type="ns2:entityRequestData" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                     <auth>
                       <citizen>
                           <signature></signature><!-- regnum.timeStamp - ийг цахим гарын үсгээрээ sign хийсэн data байна -->
                           <certFingerprint></certFingerprint><!-- Гэрчилгээжүүлэгч байгууллагаас олгосон тоон гарын үсгийн сериал дугаар -->
                           <fingerprint></fingerprint><!-- Цахим гарын үсэг хэрэглэж буй үед шаардлагагүй -->
                           <regnum></regnum><!-- Регистрийн дугаар -->
                       </citizen>
                       <operator>
                           <signature></signature><!-- regnum.timeStamp - ийг цахим гарын үсгээрээ sign хийсэн data байна -->
                           <certFingerprint></certFingerprint><!-- Гэрчилгээжүүлэгч байгууллагаас олгосон тоон гарын үсгийн сериал дугаар -->
                           <fingerprint></fingerprint><!-- Цахим гарын үсэг хэрэглэж буй үед шаардлагагүй -->
                           <regnum></regnum><!-- Регистрийн дугаар -->
                       </operator>
                     </auth>

                <!-- Веб сервисийн оролтын утгууд -->
                     <!-- Төгсгөл -->
                 </request>
                  <requestId>a3cacefd-c7b8-4ea1-8ba1-ae47c4292b59</requestId>
                  <resultCode></resultCode>
                  <resultMessage></resultMessage>
               <response>
               <!-- Веб сервисийн хариу утга буюу гаралтын утга -->
               <!-- Төгсгөл -->
                      </response>
                        </return>
                </ns2:WS100303_getLegalEntityLiqiudationInfoResponse>
                  </soap:Body>
	</soap:Envelope>

<resultCode> талбарын утга::

	OK = 0                              // амжилттай
	NOT_FOUND = 1                       // олдсонгүй
	INTERNAL_ERROR = 2                  // дотоод алдаа
	INVALID_REQUEST = 3                 // алдаатай хүсэлт
	AUTH_PART_MISSING = 200             // баталгаажуулах <auth> мэдээллийг ирүүлээгүй байна
	AUTH_CITIZEN_PART_MISSING = 201     // иргэний баталгаажуулах мэдээллийг ирүүлээгүй байна
	AUTH_OPERATOR_PART_MISSING = 202    // үйлчилгээний ажилтны баталгаажуулах мэдээллийг ирүүлээгүй байна
	ACCESS_DENIED = 203                 // хандах эрх байхгүй болно
	FINGER_TEMPLATE_NOT_FOUND = 301     // иргэний хурууны хээ бүртгэлгүй байна
	FINGERPRINT_NOT_MATCH = 302         // хуруу хээ таарахгүй байна
	FINGERPRINT_MATCH_TIMEOUT = 303     // хурууны хээ тулгах процесс хэт удаан байна
	FINGERPRINT_MATCH_ERROR = 304       // хурууны хээ тулгах процессд алдаа гарлаа
	SHOULD_RETURN_STATE_REGISTER = 401  // бүргэлийн газарт очиж бүртгэлээ шалгуулах шаардлагатай
	NOT_OWNER = 402                     // эзэмшигч биш болно

|	Та бүхэн клиент жишээ кодуудыг :ref:`эндээс<example_codes1>` харна уу.