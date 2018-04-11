#pragma comment(lib, "crypt32.lib")
#include <Windows.h>
#include <WinCrypt.h>
#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

uintptr_t pbEncBlobAddr, cbEncBlobAddr, hCryptAddr, hHandleAddr;

PCCERT_CONTEXT GetRecipientCert(HCERTSTORE hCertStore);
void MyHandleError(const char *s);
void ByteToStr(
	DWORD cb,
	void* pv,
	LPSTR sz);
BYTE *DecryptMessage(
	BYTE *pbEncryptedBlob,
	DWORD cbEncryptedBlob,
	HCRYPTPROV hCryptProv,
	HCERTSTORE hStoreHandle);
BYTE* EncryptAES();