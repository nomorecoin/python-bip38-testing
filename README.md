Python BIP0038
=======
Partial Python implementation of BIP38 - https://en.bitcoin.it/wiki/BIP_0038  
No ec-multiply modes at this time  
Encrypt function based on modified code from https://github.com/sowbug/cold-wallet-generator  
Thanks to /u/thatdontmakenosense for finishing the decrypt function  
  

CLI Usage
---------

	# Create a new BIP38 encrypted key.
	$ ./bip38.py
	Private key: <YourPrivkeyGoesHere>
	Password: <YourPasswordGoesHere>
	Confirm Password: <YourPasswordGoesHereToo>

	<AndYourShinyNewBIP38KeyComesOutHere>

	# Decrypt a BIP38 encrypted key.
	$ ./bip38.py -d
	BIP38 Encrypted Privkey: <EncryptedPrivkeyIn>
	Password: <YourPassword>

	<PlaintextPrivkeyOut>

	# or

	$ ./bip38.py -d <EncryptedPrivkeyIn>
	Password: <YourPassword>

	<PlaintextPrivkeyOut>

	# Create many BIP38 keys with the same passphrase.
	$ ./bip38.py -m
	Password: <yourpassword>
	Private key: <privkey1>
	Private key: <privkey2>
	Private key: <ENTER>
	<address1>: <encryptedprivkey1>
	<address2>: <encryptedprivkey2>
