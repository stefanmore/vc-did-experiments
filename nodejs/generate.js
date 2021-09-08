// via example from https://github.com/digitalbazaar/did-method-key-js#usage

function mapReplacer(key, value) {
  if(value instanceof Map) {
    // return {
    //   dataType: 'Map',
    //   value: Array.from(value.entries()), // or with spread: value: [...value]
    // };
    return Array.from(value.entries());
  } else {
    return value;
  }
}


const main = async function() {

	
	const didKeyDriver = require('@digitalbazaar/did-method-key').driver({
	 verificationSuite: require('@digitalbazaar/ed25519-verification-key-2020').Ed25519VerificationKey2020
	 //verificationSuite: require('@digitalbazaar/ed25519-verification-key-2018').Ed25519VerificationKey2018
	});
	// generate did:key using Ed25519 key type by default
	const {didDocument, keyPairs, methodFor} = await didKeyDriver.generate();

	// print the DID Document above
	//console.log(JSON.stringify(didDocument, null, 2));

	// print the keys
	//console.log(keyPairs);
	//console.log(JSON.stringify(keyPairs, mapReplacer, 2));


	const keyPairs2 = await didKeyDriver.verificationSuite.generate();
	//const keyPairs2 = await require('@digitalbazaar/ed25519-verification-key-2020').Ed25519VerificationKey2020.generate({});
	//const keyPairs2 = await require('@digitalbazaar/ed25519-verification-key-2018').Ed25519VerificationKey2018.generate({});
	console.log(keyPairs2.export({publicKey: true, privateKey: true}).privateKeyMultibase);
}

main();