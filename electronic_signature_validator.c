#pragma warning(disable:4996)
/*
	Using OpenSSL v.1.1.1 for platform x64.
*/
#include <stdio.h>
#include <malloc.h>
#include <memory.h>
#include <openssl/applink.c>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>


//  Function Headers
//  void fn(*void i);
void display_hash(unsigned char* data_buffer);


int main()
{
/*
	Decrypt and validate a SHA256-hashed Electronic Signature
	I: Program takes a signature file as input and its public key
   	in order to decrypt the content and compare the SHA256 hash against the original file which was signed.
	O: [0 = success] \\ [1 = fail] as "main()" function return type is an integer.
   	Comparison result as a form of hash (digest) validation.
*/
   
    	unsigned char* sig_data = NULL;
	// File pointer
	FILE* f_sig = NULL;

	// Attempt to open signature file in binary mode, store and process result
	errno_t e = fopen_s(&f_sig, "W:\\Downloads\\RSA_signature.sig", "rb");
	// Success
	if (e == 0)
	{
		FILE* pkey = NULL;
		// Process public key file
		pkey = fopen("W:\\Downloads\\pubkey_sender.pem", "r");

		RSA* apub;
		apub = RSA_new();
		apub = PEM_read_RSAPublicKey(pkey, NULL, NULL, NULL);
		fclose(pkey);

		unsigned char* buf = NULL;
		buf = (unsigned char*)malloc(RSA_size(apub));
		fread(buf, RSA_size(apub), 1, f_sig);

		// Store function result for further processing
		sig_data = (unsigned char*)malloc(16);
		RSA_public_decrypt(RSA_size(apub), buf, sig_data, apub, RSA_PKCS1_PADDING);

		// Close file
		fclose(f_sig);
		// and free dynamically allocated memory
		RSA_free(apub);
		free(buf);
		buf = NULL ; //  ##   
	}
	else
	{
		printf("\nError reading digital signature!");
		return 1;
	}

	// Success	
	printf("Hashed content from RSA-decrypted digital signature file: ");
	display_hash(sig_data);


	// Declare and initialize SHA context in order to find requested file and hash it
	SHA256_CTX ctx_sha;
	SHA256_Init(&ctx_sha);

	FILE* fp = NULL;
	// IGNIS_10M text file can be found online
	const char* file_path = "W:\\Downloads\\IGNIS_10_M.txt";
	// Read binary file function result validation; exit upon failure.
	e = fopen_s(&fp, file_path, "rb");
	if (e != 0)
		return 1;

	// Query file length in bits
	fseek(fp, 0, SEEK_END);
	int file_length = ftell(fp);
	// Reset cursor
	fseek(fp, 0, SEEK_SET);
	fread(file_buf, file_length, 1, fp);
	
	unsigned char* file_buf = NULL;
	file_buf = (unsigned char*)malloc(file_length);
	unsigned char* tmp_buf = file_buf;
	
	// Hash entire file for comparison
	// Process uses two methods, namely  "Update()" and  "Final()"	
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


	// Compute new SHA256 hash for the requested file
	unsigned char* final_digest = NULL;
	final_digest = (unsigned char*)malloc(16);
	SHA256_Final(final_digest, &ctx_sha);

	printf("\nPersonal SHA256 file hash: ");
	display_hash(final_digest);

	
	// Compare results
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

// Implementation of function header described at the beginning of program
void display_hash(unsigned char* data_buffer)
{
	char i;
	// Lowercase hexadecimal representation
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
		printf("%02x", data_buffer[i]);
	printf("\n\n");
}

