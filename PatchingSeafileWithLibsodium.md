

### Patching Seafile with Libsodium (written by linsenshiva)
Implementation:
https://github.com/orgs/auxCX/repositories

LazySodium is an implemenation of the NaCl library, a software library for network communication, encryption, decryption and signatures.

NaCl uses (XSalsa20?)(and) XChacha20 streamciphers for symmetric encryption, the Curve25519 Diffie–Hellman key-exchange function for public-key authenticated encryption, and the Poly1305 message-authentication code for message authentication. The implementation aims to be timing attack and side channel resistant.

chacha20 is an modification of salsa20 which uses a diffrent round function. ChaCha20 has a higher bit modification amount within every round which means that Chacha20 archives the same security strength like salsa20 in a shorter period of time.
XSalsa20 and XChacha20 are the extended round versions of salsa20 and chacha20. 
The nonce originally used for ChaCha20/Salsa20 was to short to get safely used with longlived keys and random strings. With XChaCha20 instead, which uses 192-bits splitted in a 128-bit nonce and the key to generate a subkey which is used as input for the original ChaCha20 and the latter 64-bit of the nonce for computing the next ChaCha20 state. Re-use of the latter 64 bit of the nonce is no security risk in this case because the subkey still must be diffrent from the last 64 bits of the original nonce.

"Assuming a secure random number generator, random 192-bit nonces should experience a single collision (with probability 50%) after roughly 2^96 messages (approximately 7.2998163e+28). A more conservative threshold (2^-32 chance of collision) still allows for 2^80 messages to be sent under a single key.

Therefore, with XChaCha20-Poly1305, users can safely generate a random 192-bit nonce for each message and not worry about nonce-reuse vulnerabilities." [https://tools.ietf.org/id/draft-irtf-cfrg-xchacha-01.html#rfc.section.2.1]

The Salsa and Chacha families use a pseudorandom function based on a so called Add-Xor-Rotate scheme per round. The ciphers have a internal state which is represented as a 4x4 matrix.
The initial state is made up of eight words of key, two words of stream position, two words of nonce (essentially additional stream position bits), and four fixed words.

In every round salsa20 uses bitwise addition (XOR), bitwies addition mod 2^32 and constant distance rotations on this matrix e.g. the internal state. Adding the mixed array in the last step to the original array makes it impossible to recover the input. You can never compute the input of a state without knowing the mixed and the original bytes array.
The keystream resulting from the modification of the state is than used to encrypt the plaintext.
So to summerize shortly ChaCha20 is an permutation of salsa20 where salsa20's quater round is replaced with another version which updates every word twice. The implication of this difference is that by changing 1 bit of the input, salsa modifies 8 bit of the output while chacha modifies 12.5 bit of the output.
 
The SecretStream API uses poly1305 to authenticate messages, which is 'A state-of-the-art secret-key message-authentication code suitable for a wide variety of applications.'
It computes a 16 byte Poly1305 authenticator for every variable-length message. It is using a 16 byte nonce, a 16 byte Key and a additional 16 byte key. It's based on treating the message as a univariate polynomial over a finite field. It is important for poly1305s security to not reuse nonce at all!

To derive a secure key for every repo from the Repo password and a repo salt we us the crypto_pw_hash function which dervices a key with Argon2.
Argon2 concatenates all the input parameters togheter and takes this input as a source of additional entropy. This is than hashed with Blake2b. Blake2b works similar to chacha20 but ChaCha operates on a 4×4 matrix where BLAKE repeatedly combines an 8-word hash value with 16 message words, truncating the ChaCha result to obtain the next hash value. A permutated copy of the input block is added with a parameter block xored with an initialization vector before each chacha round and the number of rounds is reduced from 16 (Blake) to 12 (Blake2b).
As repo salt we use the random uuid of the repo, generated with a secure random nummer generator.


public static Pair<String, String> generateKey(@NonNull String password, @NonNull byte[] salt, int version) throws Sodium exception{
        if(lazySodium.sodiumInit() != 1) throw new SodiumException("libsodium could not be initialized!");
        byte[] result = new byte[32];
        lazySodium.cryptoPwHash(
                result,
                result.length,
                password.getBytes(),
                password.length(),
                salt,
                PwHash.ARGON2ID_OPSLIMIT_INTERACTIVE,
                new NativeLong((long) PwHash.ARGON2ID_MEMLIMIT_INTERACTIVE),
                PwHash.Alg.getDefault()
        );
        return new Pair<>(lazySodium.toHexStr(result), "encKey");


This perviously derived repo encryption key now is used togheter with a randomly generated salt for deriving a per file encryption key.
The unique file salt gets prepended to the encrypted file.
We use sodiums crypto_secret_stream function with xchacha20 for encryption and poly1305 for message authentication.
The crypto_secret_stream functions requires to initialize the state of the cipher with the encryption key and produces the header and the next state wich holds key, nonce and header.
The header is needed for the initialization of the decryption so it also has to be prepended to the encrypted file.

File encryption in our patched seadroid app, Cdroid, with lazysodium and crypto_secret_stream_xchacha20_ploy1305:

(Function chunkFile, DataManager.java)
public FileBlocks chunkFile(String encKey, String enkIv, String filePath) {

        byte[] buffer = new byte[BUFFER_SIZE];
        FileBlocks seafBlock = new FileBlocks();
        int byteRead;
        int totalByteRead = 0;
        boolean success = true;

        try{
            // check if libsodium is initialized
            if(lazySodium.sodiumInit() != 1)
                throw new SodiumException("libsodium could not be initialized!");

            SecretStream.State state = new SecretStream.State();
            byte[] header = new byte[SecretStream.HEADERBYTES];

            // generate random file salt
            byte[] filesalt = lazySodium.randomBytesBuf(16);

	    // derive per file kencryption key from salt and repo encryption key
            Pair<String,String> filekeypair = Crypto.generateKey(encKey,filesalt,3);
            String filekey = filekeypair.first;
            
            // Initialize XChaCha20 state
            lazySodium.cryptoSecretStreamInitPush(state, header, lazySodium.sodiumHex2Bin(filekey));

            // write filesalt to output block
            String salt_hash = Crypto.sha1(filesalt);
            File s = new File(storageManager.getTempDir(), salt_hash);
            Block salt_block = new Block(salt_hash,s.getAbsolutePath(),salt_hash.length(), 0L);
            seafBlock.blocks.add(salt_block);
            FileOutputStream out = new FileOutputStream(s);
            DataOutputStream dos = new DataOutputStream(out);
            dos.write(filesalt);
            dos.close();

            // write header to next output block
	    // sha1 hash of block is used as blockid

            final String hdid = Crypto.sha1(header);
            File hd = new File(storageManager.getTempDir(), hdid);
            Block header_block = new Block(hdid, hd.getAbsolutePath(), hd.length(), 0L);
            seafBlock.blocks.add(header_block);
            out = new FileOutputStream(hd);
            dos = new DataOutputStream(out);
            dos.write(header);
            dos.close();

            File file = new File(filePath);
            FileInputStream in = new FileInputStream(file);
            DataInputStream dis = new DataInputStream(in);


            // encryption of the buffered plaintext
            while ((byteRead = dis.read(buffer, 0, BUFFER_SIZE)) != -1) {
                totalByteRead += byteRead;
                byte[] cipher = new byte[byteRead + SecretStream.ABYTES];
                if (byteRead < BUFFER_SIZE) {
                    buffer = Arrays.copyOfRange(buffer, 0, byteRead);
                }

		// add SecretStream.FINAL_TAG to crypto_secretstream to mark end of the stream and erase the secret key used to encrypt the previous sequence

                if(totalByteRead == file.length()) {
                    success = lazySodium.cryptoSecretStreamPush(
                            state,
                            cipher,
                            buffer,
                            byteRead,
                            SecretStream.TAG_FINAL
                    );
                }else{
                    success = lazySodium.cryptoSecretStreamPush(
                            state,
                            cipher,
                            buffer,
                            byteRead,
                            SecretStream.TAG_MESSAGE
                    );
                }
                if(!success) {
                    throw new SodiumException("Encryption failed!");
                }

	        // write encrypted blocks
                final String blkid = Crypto.sha1(cipher);
                File blk = new File(storageManager.getTempDir(), blkid);
                Block block = new Block(blkid, blk.getAbsolutePath(), blk.length(), 0L);
                seafBlock.blocks.add(block);
                out = new FileOutputStream(blk);
                dos = new DataOutputStream(out);
                dos.write(cipher);
                dos.close();
                buffer = new byte[BUFFER_SIZE];
            }
            in.close();
            return seafBlock;
        }catch (IOException g){
            g.printStackTrace();
            return null;
        }catch(SodiumException e){
            e.printStackTrace();
        }

        return null;
    }


decryption looks like the following (Function getFileByBlocks, DataManager.java):
/* ...... */
boolean first = true;
         boolean second = false;
         FileOutputStream out = new FileOutputStream(localFile);
         DataOutputStream dos = new DataOutputStream(out);
         byte[] header = new byte[SecretStream.HEADERBYTES];
         byte[] salt = new byte[16];
         byte[] tag = new byte[1];
         String filekey = "";

         if(lazySodium.sodiumInit() != 1)
		throw new SodiumException("libsodium is not initialized!");
         SecretStream.State state = new SecretStream.State();
         for (Block blk : fileBlocks.blocks) {

                File tempBlock = new File(storageManager.getTempDir(), blk.blockId);
                final Pair<String, File> block = sc.getBlock(repoID, fileBlocks, blk.blockId, 	tempBlock.getPath(), fileSize, monitor);
                FileInputStream in = new FileInputStream(block.second);
                DataInputStream dis = new DataInputStream(in);

                //read salt from first block
                if(first){
                    	dis.read(salt);
                    	dis.close();

	   	    	// derive per file encryption key from salt and repo encryption key
                    	filekey = Crypto.generateKey(encKey,salt,3).first;

                    	second = true;
                    	first = false;

		//read header from second block
                }else if(second){
                        if(filekey.compareTo("") == 0){
                	       	throw new SodiumException("fileKey generation failed!");
                	}
                	dis.read(header);
                	dis.close();

       	        	//Initialize state with header and key
                	lazySodium.cryptoSecretStreamInitPull(
				state,
 				header,
				lazySodium.sodiumHex2Bin(filekey)
		 	);
                      	second = false;

		// read cipher text from blocks                
		}else{
                       byte[] cipher = new byte[(int)block.second.length()];
                       dis.read(cipher);
                       byte[] message = new byte[(int)block.second.length() - SecretStream.ABYTES];
		     
		       // decrypt ciphertext

                       if(!lazySodium.cryptoSecretStreamPull(
   			    	state, 
 				message, 
				tag, 
				cipher, 
				cipher.length
		        )){
                       		throw new SodiumException("File decryption fails!");
                	}
                	dos.write(message);
           	}
           }
           dos.close();
           out.close();
/* ...... */

After implementing those features we were surprised how easy it was to replace seafiles cryptoscheme with our secure version of it. Since we didn't change anything at seafiles program flow and the server api we believed for a short moment that our solution worked as an complete drop in replacement for seafiles client 'seadroid'. To easy. Soon we realized that the functions we patched for encrypted file up- and download didn't get called at all during 'encrypted' file upload/download.

It is possible to use our client instead of seafiles client togtheter with any seafile server, since this works as a drop in replacement for seadroid. Of course we should not be able to decrypted any files uploaded and encrypted with seafiles seadroid client and the other way arround.

Since we wanted to know for sure if our encryption function really weren't called at all ( We actually already knew since the logging output for these functions was missing), we tried to open a file with the latest stable seafile client (seadroid-2.2.22), which we previously encrypted and uploaded to the sefaile server with our libsodium replacement 'cDroid'. The unpatched seadroid client should not be able to decrypt and open that file.
Against our assumption we were able to decrypt and download the file with the latest seadroid client.

That means either that the server must have decrypted the previously encrypted and uploaded file by himself because it's not possible to decrypt sodium encrypted data with the seafile encryption scheme since they use AES-CBC or data doesn't get encrypted at all.
With the help of the debugger and a lot of code auditing we found the following function in the PasswordDialog class:


    protected void runTask() {
        SeafRepoEncrypt repo = dataManager.getCachedRepoEncryptByID(repoID);
        try {
            if (repo == null || !repo.canLocalDecrypt()) {  // repo can local decrypt???
                dataManager.setPassword(repoID, password);
            } else {
                Crypto.verifyRepoPassword(repoID, password, repo.encVersion, repo.magic);
            }
        } catch (SeafException e) {
            setTaskException(e);
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }
}


 
Each repo has an variable which defines if it can encrypt and decrypt locally. That means you have to enable client side encryption in the settings of the app. In the SettingsManager class of the app you can see that the default value for local de- and encryption is set to false.
It is quite misleading that when you setup a new Library, you get asked if you want to encrypt the library and - if thats the case - you submit a password for the new repo.
From the seafile server manual you can find out that "The client side encryption works on iOS client since version 2.1.6. The Android client support client side encryption since version 2.1.0.". These information leads to the assumption that seadroid encryptes client side by default.
This is obviously not the case since we just discovered that it is not possible to encrypt or decrypt on client side out of the box.

Screenshot-encryption-not-setup


public boolean isEncryptEnabled() {
        return settingsSharedPref.getBoolean(CLIENT_ENC_SWITCH_KEY, /*default value*/ false);
}

This just seems like a joke. Of course, client side encryption works. Not a lie. But that you have to enable local encryption in the settings you can read nowhere and the seafile server manual makes it sound like this works by default.
After setting client side encryption to true, encryption and decryption works as expected.

Screenshot-encryption-setup

public boolean isEncryptEnabled() {
        return settingsSharedPref.getBoolean(CLIENT_ENC_SWITCH_KEY, true); // now enabled by default
}
//With this discoveries our trust in seafiles promisses vanishes more and more.



Wireshark sniffing of seadroid requests

The fact that we were able to decrypt a file which has been encrypted with a patched version of the client with the the seadroid client made us think about the server a bit more. Since we luckily can exclude the case szenario in which seafile doens't encrypt data at all, we can move on to another problem.
In case encryption is enabled, everything is more or less fine. What happends if that is not the case here. Seadroid will send your repo encryption password to the server and the server than encryptes your files with your from your password and random_key derived repo encryption password. Just for interest, we tested if the password also leaks when encryption is enabled and the client actually does encrypt data locally.

Steps to reproduce:

Clone the latest stable seadroid client.

git clone https://github.com/haiwen/saedroid.git

setup an developement environment for android with an android emulator. 

setup a local seafile docker container in your home net
(use seafiles docker-compose file for that, default configuration makes seahub/ seafile listen on localhost:80)

start container with docker-compose up 
or start container in background with docker-compose up -d

setup seadroid
move key.properties.example to key.properties
build project using gradle

Add Account
Add your local seafile server url. Since we want to access the loopback from the emulator we have to use the address that represents the host machine to the emulator, in my case this was http://10.0.2.2:80
instead of http://127.0.0.1:80 .
Create an user account in your webinterface by accessing http://127.0.0.1:8000 in your web browser.
Use your fresh registered user to log in seafiles android client.

Install wireshark on your host machine
choose loopback as listen interface in the first dialog.

Switch to seadroid and set up an encrypted repo.

Screenshot-setup-encrypted-library

After this task was successfull, go to wireshark and set 'http' as filter and stop the recording of packets by pressing the red Button on the left corner.

You should see some requests to the seafile api. Take a closer look at the post requests and the data applied to the request.

When you open the request body you should see a similar output to the following picture:

Screenshot-wireshark-password.leak-setuo-enrypted-library


Sadly it doens't matter if encryption is enabled or disabled. While setting up an encrypted repo with seadroid your password will leak in plaintext to the seafile server.
The password leaks again to the server, even though local decryption is enabled.
And this discovery is damn fucking worse then all the other problems before.
Client side encryption is enabled but the client still sends the repos encryption password to the server.
This makes client side encryption totally obsolete, since the server and any man-in-the-middle might be able to receive your password!

To cititate seafiles server manual one more time:
"CAUTION: The client side encryption does currently NOT work while using the web browser and the cloud file explorer of the desktop client. When you are browsing encrypted libraries via the web browser or the cloud file explorer, you need to input the password and the server is going to use the password to decrypt the "file key" for the library (see description below) and cache the password in memory for one hour. The plain text password is never stored or cached on the server."
Did the forgot to mention that seadroid also sends the password to the server? Are they going to explain that the passwords gets send to the server in plaintext, but the server never stores it in plaintext?? And obviously the server doesnt have to cache the password because everytime we encrypt something on clients side the password will get sent to the server again and again.






























