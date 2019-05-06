var standard_input = process.stdin;
const utf8 = require('utf8');
var sd = require('string_decoder').StringDecoder;
var d = new sd('utf8');
var crypto = require('crypto');

var ursa = require('ursa');

var keys = ursa.generatePrivateKey();

var privPem = keys.toPrivatePem('utf8');

var priv = ursa.createPrivateKey(privPem, '', 'utf8');

var pubPem = keys.toPublicPem('utf8');

var pub = ursa.createPublicKey(pubPem, 'utf8');

const NodeRSA = require('node-rsa');
const key = new NodeRSA();
/*
var signer = ursa.createSigner('sha256');
signer.update('hola');
var ret = signer.sign(priv, 'utf8');
console.log("The signed value is: " + ret);

var verifier = ursa.createVerifier('sha256');
verifier.update('hola', 'utf8');
var ret2 = verifier.verify(pub, ret, 'utf8');
console.log(ret2);
*/
/*
var sign = crypto.createSign('RSA-SHA256');
sign.update('hola');
var signature = sign.sign(Buffer(priv.toString()), 'utf8');

console.log(signature);

var verifier = crypto.createVerify('RSA-SHA256');
verifier.update(signature, 'utf8');
const publicKeyBuf = new Buffer(pub, 'utf8');
const signatureBuf = new Buffer(signature, 'utf8');
result = verifier.verify(pulicKeyBuf, SignatureBuf);
console.log(result);
*/




console.log("Choose one of the following options: \n 1. Encrypt \n 2. Decrypt \n 3. Sign \n 4. Verify \n");

standard_input.on('data', function(data) {
	if(data == 1) {
		console.log("Please enter the data you want encrypted: ");
		standard_input.on('data', function(data) {
			var str = data.toString();
			var encryptedData = pub.encrypt(str);
			var encryptedDataDecoded = d.write(encryptedData);
			console.log("Encrypted string is: " + encryptedDataDecoded);
		});	
	}
	else if(data == 2) {
		console.log("Please enter the data you want decrypted: ");
		standard_input.on('data', function(data) {
			var str = data.toString();
			var decryptedData = priv.decrypt(str);
			var decryptedDataDecoded = d.write(decryptedData);
			console.log("Decrypted string is: " + decryptedDataDecoded);
		});
	}
	else if(data == 3) {
		console.log("Please enter the data you would like signed: ");
		standard_input.on('data', function(data) {
			var str = data.toString();
			var buf = Buffer(str);
			var signer = ursa.createSigner('sha256');
			signer.update(buf);
			var ret = signer.sign(priv, 'utf8');
			console.log("The signed value is: " + ret);
		});
	}
	else if (data == 4) {
		console.log("Please enter the data you would like verified: ");
		standard_input.on('data', function(data) {
			var str = data.toString();
			var buf = Buffer(str);
			var verifier = ursa.createVerifier('sha256');
			verifier.update('buf', 'utf8');
			var ret = verifier.verify(pub, 'buf', 'utf8');
			console.log(ret);


			/*var verifier = crypto.createVerify('sha256');
			verifier.update(sign);
			var ver  = verifier.verify(publicKey, sign, 'base64');
			console.log(ver)*/
		});
	}
});

/*var string = "hello world";

var encrypted = pub.encrypt(string);
var encryptedDecoded = d.write(encrypted);
console.log("Encrypted string is: " + encryptedDecoded);

var decrypted = priv.decrypt(encrypted);
var decryptedDecoded = d.write(decrypted);

console.log("Decrypted string is: " + decryptedDecoded);*/