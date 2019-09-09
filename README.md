# verter
https://www.youtube.com/watch?v=jN6_rO2rYA8

Искусственный идиот 3 поколения.
С трудом выполняет задачу подписания XML по этой мантре https://www.w3.org/TR/xmldsig-core/
Еще с большим трудом может проверить подпись.

!!! ОБЯЗАТЕЛЬНЫЕ ВВОДНЫЕ И ОГРАНИЧЕНИЯ !!!

Работает только с запросами вида

=====================================================
<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><soapenv:Body Id="Body">
	... само тело ...
</soapenv:Body></soapenv:Envelope>
=====================================================

Обязательно ДОЛЖЕН БЫТЬ атрибут Id="Body" внутри soapenv:Body. Подписывается только этот элемент
Для ключей поддерживается только формат JKS - на входе должен быть 1 файл
Все параметры подписания захардкожены - вид SigndeInfo следующий
Элемент Signature всегда будет находится внутри элемента soapenv:Header
===================================================== 
			<ds:SignedInfo>
				<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
				<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
				<ds:Reference URI="#Body">
					<ds:Transforms>
						<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
						<ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"/>
					</ds:Transforms>
					<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
					<ds:DigestValue>4avmFNiRLneYMB3/hNSu3Mw4zg8=</ds:DigestValue>
				</ds:Reference>
			</ds:SignedInfo>
=====================================================

Запуск. Параметры

start java -jar verter-1.0-SNAPSHOT-jar-with-dependencies.jar <путь к файлу ключей> <PRIVATE KEY ALIAS> <PRIVATE KEY PASS> <KEY STORE PASS> <KEY STORE TYPE> <LISTEN PORT> <VALIDATOR URI> <iSIGNER URI> <HLR URI>

Пример 
start java -jar verter-1.0-SNAPSHOT-jar-with-dependencies.jar c:\UCELL\data\private_key.keystore AAA BBB CCC JKS 19999 /VALIDATE /SIGN http://localhost:19999/VALIDATE 







