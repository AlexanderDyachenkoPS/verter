# verter
https://www.youtube.com/watch?v=jN6_rO2rYA8

������������� ����� 3 ���������.
� ������ ��������� ������ ���������� XML �� ���� ������ https://www.w3.org/TR/xmldsig-core/
��� � ������� ������ ����� ��������� �������.

!!! ������������ ������� � ����������� !!!

�������� ������ � ��������� ����

=====================================================
<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><soapenv:Body Id="Body">
	... ���� ���� ...
</soapenv:Body></soapenv:Envelope>
=====================================================

����������� ������ ���� ������� Id="Body" ������ soapenv:Body. ������������� ������ ���� �������
��� ������ �������������� ������ ������ JKS - �� ����� ������ ���� 1 ����
��� ��������� ���������� ������������ - ��� SigndeInfo ���������
������� Signature ������ ����� ��������� ������ �������� soapenv:Header
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

������. ���������

start java -jar verter-1.0-SNAPSHOT-jar-with-dependencies.jar <���� � ����� ������> <PRIVATE KEY ALIAS> <PRIVATE KEY PASS> <KEY STORE PASS> <KEY STORE TYPE> <LISTEN PORT> <VALIDATOR URI> <iSIGNER URI> <HLR URI>

������ 
start java -jar verter-1.0-SNAPSHOT-jar-with-dependencies.jar c:\UCELL\data\private_key.keystore AAA BBB CCC JKS 19999 /VALIDATE /SIGN http://localhost:19999/VALIDATE 







