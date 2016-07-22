package main

var clientHello = []byte{
	0x16,       //Content Type: Handshake (22)
	0x03, 0x01, //Version: TLS 1.0 (0x0301)
	0x00, 0x45, //Length: 69

	0x01,             //Handshake Type: Client Hello (1)
	0x00, 0x00, 0x41, //Length: 65
	0x03, 0x03, //Version: TLS 1.2 (0x0303)
	0x1c, 0x32, 0xdb, 0xd9, 0x3c, 0x12, 0x75, 0x93, //Random Bytes
	0xaf, 0x9b, 0x8b, 0x7c, 0xa1, 0x48, 0x66, 0xaa,
	0x37, 0xbf, 0xfb, 0xad, 0xda, 0x46, 0xdd, 0x95,
	0xc6, 0x6e, 0xdd, 0x79, 0x59, 0xfd, 0xba, 0xff,
	0x00,       //Session ID Length: 0
	0x00, 0x02, //Cipher Suites Length: 2
	0x00, 0x9c, //Cipher Suite: TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c)
	//0xc0, 0x2f, //Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)
	0x01, 0x00, //No compression
	0x00, 0x16, //Extension Length: 22

	0x00, 0x0a, //Extension Type: elliptic_curves (0x000a)
	0x00, 0x04, //Extension Length: 4
	0x00, 0x02, //Elliptic Curves Length: 2
	0x00, 0x17, //Elliptic curve: secp256r1 (0x0017)

	0x00, 0x0b, //Extension Type: ec_point_formats (0x000b)
	0x00, 0x02, //Extension Length: 2
	0x01, //EC point formats Length: 1
	0x00, //EC point format: uncompressed (0)

	0x00, 0x0d, //Extension Type: signature_algorithms (0x000d)
	0x00, 0x04, //Extension Length: 4
	0x00, 0x02, //Signature Hash Algorithms Length: 2
	0x04, 0x01, //Signature Hash Algorithm: RSA with SHA256

}
