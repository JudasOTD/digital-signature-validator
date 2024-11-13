#pragma warning(disable:4996)
#include <openssl/applink.c>
#define SHA256_DIGEST_LENGTH 32
/*
	Using OpenSSL v.1.1.1 for platform x64.
*/
#include <memory.h>
#include <malloc.h>
#include <stdio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>


/*
	I:  Program takes a signature file as input and its public key
	in order to decrypt the content and compare the SHA256 hash against the original file which was signed.
	O:  Comparison result as a form of hash (digest) validation,
	which could be either [0 = success] \\ [1 = fail] as 'main()' function return type is an integer.
*/

// void *fn(void* i);
int main() 
{
	// File pointer
	FILE* f_sig = NULL;
	unsigned char* sig_data = NULL;

	// Decrypt and validate a SHA256 hashed Electronic Signature, attempt to open file in binary mode, store and process result.
	errno_t e = fopen_s(&f_sig, "W:\\Downloads\\RSA_signature.sig", "rb");
	// Success
	if (e == 0)
	{
		// Process public key file.
		FILE* pkey = NULL;
		pkey = fopen("W:\\Downloads\\pubkey_sender.pem", "r");

		RSA* apub;
		apub = RSA_new();
		apub = PEM_read_RSAPublicKey(pkey, NULL, NULL, NULL);
		fclose(pkey);


		unsigned char* buf = NULL;
		buf = (unsigned char*)malloc(RSA_size(apub));
		fread(buf, RSA_size(apub), 1, f_sig);


		// Store function result for further processing.
		sig_data = (unsigned char*)malloc(16);
		RSA_public_decrypt(RSA_size(apub), buf, sig_data, apub, RSA_PKCS1_PADDING);
		// Close file
		fclose(f_sig);
		// And free dinamically allocated memory...
		free(buf);
		RSA_free(apub);
	}
	else
	{
		printf("\n\nError reading digital signature!");
		return 1;
	}

	// Success	
	printf("Hashed content from RSA-decrypted electronic signature file:  ");
	// Lowercase hexadecimal representation
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
		printf("%2x", sig_data[i]);
	printf("\n\n");
	
	
	// Compute new SHA256 hash for requested file.
	unsigned char final_digest[SHA256_DIGEST_LENGTH];
	// Declare and initialize SHA context.
	SHA256_CTX ctx_sha;
	SHA256_Init(&ctx_sha);

	FILE* fp = NULL;
	// IGNIS_10M text file can be found online.
	const char* file_path = "W:\\Downloads\\IGNIS_10_M.txt";
	unsigned char* file_buf = NULL;

	// Read binary file function result validation; exit upon failure.
	e = fopen_s(&fp, file_path, "rb");
	if (e != 0)
		return 1;
	
	// Query file length in bits.
	fseek(fp, 0, SEEK_END);
	int file_length = ftell(fp);
	file_buf = (unsigned char*)malloc(file_length);
	//  pointer
	unsigned char* tmp_buf = file_buf;
	// Reset cursor.
	fseek(fp, 0, SEEK_SET);
	fread(file_buf, file_length, 1, fp);


	// Hash entire file for comparison
	// Process uses two methods, namely  'Update()' and  'Final()'	
	while (file_length > 0)
	{
		if (file_length > 128)
			SHA256_Update(&ctx_sha, tmp_buf, 128);
		else
			SHA256_Update(&ctx_sha, tmp_buf, file_length);

		// Decrement
		file_length -= 128;
		tmp_buf += 128;
	}
	fclose(fp);
	SHA256_Final(final_digest, &ctx_sha);

	printf("\nPersonal file SHA256 hash:  ");
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
		printf("%02x", final_digest[i]);
	printf("\n\n");


	// Compare the results
	if (memcmp(sig_data, final_digest, 16) == 0)
	{
		printf("\n\nSignature OK!\n");
		return 0;
	}
	else
	{
		printf("\n\nSignature is WRONG!\n");
		return 1;
	}
}



