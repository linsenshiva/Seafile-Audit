
###Abstract
===========

For a long time there had been the common believe that free and open source software is inherently secure just because of the fact people have the opportunity to read its source code. At the latest with the disclosure of the infamous heartbleed vulnerability in 2014 it became obvious that this believe is fundamentally wrong. Today - almost 6 years later - there's still a lack of peer reviewing in many open source projects, which I will outline in the following example.
For a long period time - although there had been a huge demand for clientside encryption by the communiy - there only were a few open source pojects that
actually implemented that feauture. For file storage one of the only players that offered and advertised end-to-end-encryption from the beginning on was Seafile. There-
for it is countlessly mentioned all over the internet in articles and forum threads.

When I recently decided to use Seafile for one of my own projects I started auditing its source code in order to judge its feasability. While the gerneral code quality is very good and structured, I was surprised when I had a look at the module that is responsible for clientside encryption. It became clear to me pretty quickly that the roughly 200 lines of code are scattered with some of the most common implementation errors in computer programs dealing with cryptography. In the following I will
examplarily walk you through the code dealing with encryption and decryption in Seafile's android client and analyze found errors and their impact one by
one. Finally I will propose a dead simple fix for all discovered problems.

I want to point out that we don't want to harm Seafile, haiwen or any of its userbase in any way. We tried to responsibly disclose our findings but our request simply has been ignored until now.
Thats why we now publish our findings here.

###Code Analysis
================

The following code is taken directly from Seadroid 2 without
modifications except that comments and import statements were removed
for compactness.
 
 
 ```java
 package com.seafile.seadroid2.crypto;

import android.support.annotation.NonNull;
import android.util.Base64;
import android.util.Log;
import android.util.Pair;

import com.seafile.seadroid2.SeafException;

import org.spongycastle.crypto.PBEParametersGenerator;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.spongycastle.crypto.params.KeyParameter;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * There are a few ways to derive keys, but most of them are not particularly secure.
 * To ensure encryption keys are both sufficiently random and hard to brute force, we should use standard PBE key derivation methods.
 * Other Seafile platforms, e.g, server side, using PBKDF2WithHmacSHA256 to derive a key/iv pair from the password,
 * using AES 256/CBC to encrypt the data.
 * <p/>
 * Unfortunately, Android SDK doesn`t support PBKDF2WithHmacSHA256, so we use Spongy Castle, which is the stock Bouncy Castle libraries with a couple of small changes to make it work on Android.
 * For version 1.47 or higher of SpongyCastle, we can invoke PBKDF2WithHmacSHA256 directly,
 * but for versions below 1.47, we could not specify SHA256 digest and it defaulted to SHA1.
 * see
 * 1. https://rtyley.github.io/spongycastle/
 * 2. http://stackoverflow.com/a/15303291/3962551
 * 3. https://en.wikipedia.org/wiki/Bouncy_Castle_(cryptography)
 */
public class Crypto {
    private static final String TAG = Crypto.class.getSimpleName();

    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS7Padding";
    private static final String CHAR_SET = "UTF-8";

    private static int KEY_LENGTH = 32;
    private static int KEY_LENGTH_SHORT = 16;
    private static int ITERATION_COUNT = 1000;
    // Should generate random salt for each repo
    private static byte[] salt = {(byte) 0xda, (byte) 0x90, (byte) 0x45, (byte) 0xc3, (byte) 0x06, (byte) 0xc7, (byte) 0xcc, (byte) 0x26};

    static {
        // http://stackoverflow.com/questions/6898801/how-to-include-the-spongy-castle-jar-in-android
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
    }

    private Crypto() {
    }

    /**
     * When you view an encrypted library, the client needs to verify your password.
     * When you create the library, a "magic token" is derived from the library id and password.
     * This token is stored with the library on the server side.
     * <p/>
     * The client use this token to check whether your password is correct before you view the library.
     * The magic token is generated by PBKDF2 algorithm with 1000 iterations of SHA256 hash.
     *
     * @param repoID
     * @param password
     * @param version
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private static byte[] generateMagic(String repoID, String password, int version) throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException, SeafException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        if (version != 1 && version != 2) {
            throw SeafException.unsupportedEncVersion;
        }

        return deriveKey(repoID + password, version);
    }

    /**
     * Recompute the magic and compare it with the one comes with the repo.
     *
     * @param repoId
     * @param password
     * @param version
     * @param magic
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws UnsupportedEncodingException
     * @throws SeafException
     */
    public static void verifyRepoPassword(String repoId, String password, int version, String magic) throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException, SeafException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {
        final byte[] generateMagic = generateMagic(repoId, password, version);
        final byte[] genMagic = toHex(generateMagic).getBytes(CHAR_SET);
        final byte[] repoMagic = magic.getBytes(CHAR_SET);
        int diff = genMagic.length ^ repoMagic.length;
        for (int i = 0; i < genMagic.length && i < repoMagic.length; i++) {
            diff |= genMagic[i] ^ repoMagic[i];
        }

        if (diff != 0) throw SeafException.invalidPassword;
    }

    /**
     * First use PBKDF2 algorithm (1000 iteratioins of SHA256) to derive a key/iv pair from the password,
     * then use AES 256/CBC to decrypt the "file key" from randomKey (the "encrypted file key").
     * The client only saves the key/iv pair derived from the "file key", which is used to decrypt the data.
     *
     * @param password
     * @param randomKey encrypted file key
     * @param version
     * @return
     * @throws UnsupportedEncodingException
     * @throws NoSuchAlgorithmException
     */
    public static Pair<String, String> generateKey(@NonNull String password, @NonNull String randomKey, int version) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        // derive a key/iv pair from the password
        final byte[] key = deriveKey(password, version);
        SecretKey derivedKey = new SecretKeySpec(key, "AES");
        final byte[] iv = deriveIv(key);

        // decrypt the file key from the encrypted file key
        final byte[] fileKey = seafileDecrypt(fromHex(randomKey), derivedKey, iv);
        // The client only saves the key/iv pair derived from the "file key", which is used to decrypt the data
        final String encKey = deriveKey(fileKey, version);
        return new Pair<>(encKey, toHex(deriveIv(fromHex(encKey))));
    }

    /**
     * Derive secret key by PBKDF2 algorithm (1000 iterations of SHA256)
     *
     * @param password
     * @param version
     * @return
     * @throws UnsupportedEncodingException
     * @throws NoSuchAlgorithmException
     */
    private static byte[] deriveKey(@NonNull String password, int version) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA256Digest());
        gen.init(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password.toCharArray()), salt, ITERATION_COUNT);
        return ((KeyParameter) gen.generateDerivedMacParameters(version == 2 ? KEY_LENGTH * 8 : KEY_LENGTH_SHORT * 8)).getKey();
    }

    /**
     * Derive secret key by PBKDF2 algorithm (1000 iterations of SHA256)
     *
     * @param fileKey
     * @param version
     * @return
     * @throws UnsupportedEncodingException
     * @throws NoSuchAlgorithmException
     */
    private static String deriveKey(@NonNull byte[] fileKey, int version) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        try {
            PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA256Digest());
            gen.init(fileKey, salt, ITERATION_COUNT);
            byte[] keyBytes = ((KeyParameter) gen.generateDerivedMacParameters(version == 2 ? KEY_LENGTH * 8 : KEY_LENGTH_SHORT * 8)).getKey();
            return toHex(keyBytes);
        } catch (Exception e) {
            e.printStackTrace();
            throw new IllegalArgumentException(" Attempt to get length of null array");
        }
    }

    /**
     * Derive initial vector by PBKDF2 algorithm (10 iterations of SHA256)
     *
     * @param key
     * @return
     * @throws UnsupportedEncodingException
     */
    private static byte[] deriveIv(@NonNull byte[] key) throws UnsupportedEncodingException {
        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA256Digest());
        gen.init(key, salt, 10);
        return ((KeyParameter) gen.generateDerivedMacParameters(KEY_LENGTH_SHORT * 8)).getKey();
    }

    /**
     * Do the decryption
     *
     * @param bytes
     * @param key
     * @param iv
     * @return
     */
    private static byte[] seafileDecrypt(@NonNull byte[] bytes, @NonNull SecretKey key, @NonNull byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
            return cipher.doFinal(bytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            Log.e(TAG, "NoSuchAlgorithmException " + e.getMessage());
            return null;
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            Log.e(TAG, "InvalidKeyException " + e.getMessage());
            return null;
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            Log.e(TAG, "NoSuchPaddingException " + e.getMessage());
            return null;
        } catch (BadPaddingException e) {
            e.printStackTrace();
            Log.e(TAG, "seafileDecrypt BadPaddingException " + e.getMessage());
            return null;
        } catch (IllegalBlockSizeException e) {
            Log.e(TAG, "IllegalBlockSizeException " + e.getMessage());
            e.printStackTrace();
            return null;
        } catch (InvalidAlgorithmParameterException e) {
            Log.e(TAG, "InvalidAlgorithmParameterException " + e.getMessage());
            e.printStackTrace();
            return null;
        }

    }

    /**
     * Do the encryption
     *
     * @param plaintext
     * @param inputLen
     * @param key
     * @param iv
     * @return
     */
    private static byte[] seafileEncrypt(@NonNull byte[] plaintext, int inputLen, @NonNull SecretKey key, @NonNull byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            IvParameterSpec ivParams = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, ivParams);
            return cipher.doFinal(plaintext, 0, inputLen);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            Log.e(TAG, "NoSuchAlgorithmException " + e.getMessage());
            return null;
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            Log.e(TAG, "InvalidKeyException " + e.getMessage());
            return null;
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            Log.e(TAG, "InvalidAlgorithmParameterException " + e.getMessage());
            return null;
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            Log.e(TAG, "NoSuchPaddingException " + e.getMessage());
            return null;
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
            Log.e(TAG, "IllegalBlockSizeException " + e.getMessage());
            return null;
        } catch (BadPaddingException e) {
            e.printStackTrace();
            Log.e(TAG, "seafileEncrypt BadPaddingException " + e.getMessage());
            return null;
        }
    }

    /**
     * All file data is encrypted by the encKey/encIv with AES 256/CBC.
     *
     * @param plaintext
     * @param encKey
     * @param iv
     * @return
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     */
    public static byte[] encrypt(@NonNull byte[] plaintext, @NonNull String encKey, @NonNull String iv) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        return encrypt(plaintext, plaintext.length, encKey, iv);
    }

    /**
     * All file data is encrypted by the encKey/encIv with AES 256/CBC.
     *
     * @param plaintext
     * @param inputLen
     * @param encKey
     * @param iv
     * @return
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     */
    public static byte[] encrypt(@NonNull byte[] plaintext, int inputLen, @NonNull String encKey, @NonNull String iv) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        SecretKey secretKey = new SecretKeySpec(fromHex(encKey), "AES");
        return seafileEncrypt(plaintext, inputLen, secretKey, fromHex(iv));
    }

    /**
     * All file data is decrypted by the encKey/encIv with AES 256/CBC.
     *
     * @param plaintext
     * @param encKey
     * @param iv
     * @return
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     */
    public static byte[] decrypt(@NonNull byte[] plaintext, @NonNull String encKey, @NonNull String iv) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        SecretKey realKey = new SecretKeySpec(fromHex(encKey), "AES");
        return seafileDecrypt(plaintext, realKey, fromHex(iv));
    }

    /**
     * Convert byte to Hexadecimal
     *
     * @param buf
     * @return
     */
    private static String toHex(@NonNull byte[] buf) {
        if (buf == null) return "";

        String hex = "0123456789abcdef";

        StringBuilder result = new StringBuilder(2 * buf.length);
        for (int i = 0; i < buf.length; i++) {
            result.append(hex.charAt((buf[i] >> 4) & 0x0f)).append(hex.charAt(buf[i] & 0x0f));

        }
        return result.toString();
    }

    /**
     * Convert Hexadecimal to byte
     *
     * @param hex
     * @return
     * @throws NoSuchAlgorithmException
     */
    private static byte[] fromHex(@NonNull String hex) throws NoSuchAlgorithmException {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return bytes;
    }

    public static String toBase64(byte[] bytes) {
        return Base64.encodeToString(bytes, Base64.NO_WRAP);
    }

    public static byte[] fromBase64(String base64) {
        return Base64.decode(base64, Base64.NO_WRAP);
    }

    public static String sha1(@NonNull byte[] cipher) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(cipher, 0, cipher.length);
        return toHex(md.digest());
    }
}
java```


#### I will discuss the flaws and their impact on Seafiles general security and possible solutions one by one in the following section. In the end I will propose a dead simple fix for all the addressed issues. Note that the problems are ordered by occurence from top to bottom.

Hardcoded salt
--------------

While this doesn't break the cryptographic security of Seafile in any
way, it has significant impact on the feasability of some attacks and
makes Seafile susceptible to common user errors such as choosing weak
passwords. Since the impact of this implementation error has been
analyzed in cryptographic literature countless times, I only briefly
summarize it and give reference for further reading. Basically the only
reason salts were invented was to prevent an attacker from having the
ability of using preassambled password lists to perform dictionary
attacks. The idea is the following: Instead of using the users password
or a hash of it directly the server would generate and store a random
string for each user during registration. The password then would be
combined with the salt and a password deriving function - usually a
cryptographic hash function applied to the previous round's result and
the original password - to derive the actual key used for encryption.
Because of this the attacker would be forced to reassamble the
passwordlist for each user and thereby drastically increase the time and
computing power needed to test all passwords contained in the password list. In other words:
The attacker would have to create a new password list for each user and
each database preventing him to precompute it. [citation needed]

Using a hardcoded salt completely undermines all mentioned advantages of using a salt/PBKDF at
all. While this doesn't influence the basic cryptographic security of
Seafile the past has shown that it's unlikely users will ever start
using safe passwords so neglegting this feature isn't an option.
Obviously the fix for this - funily mentioned in the comment directly
above the significant line of code - would be generate the
salt for each user randomly during account creation. As this is already
done for deriving the authenticaton password anyway one could simply
reuse this salt. The fact that the salt was already used to derive the
authentication password doesn't influence the mentioned effects on
password security in any way - assuming encryption keys are never
derived from the users authentication password and if so, a different
number of iterations is used. [citation needed - libsodium docs]

Use of AES-CBC in combination with missing authentication
---------------------------------------------------------

The ciphermode used for encryption is AES-CBC. Although there are currently no known attacks on the confidentiality of AES-CBC, when used without message authentication it becomes vulnerable to a whole class of well studied cryptographic attacks. Eventhough the attacker still can't calculate the plaintext corresponding to an encrypted message - thus preserving confidentiality - the lack of authentication makes this mode of operation vulnerable to malleability which was shown by Moxie Marlinspike et al. in [citation needed].

Simply said: While the server/MITM still is not able to see the plaintext corresponding to a file it's able to inject arbritary plaintext without the user's knowledge which can pose a huge problem and open many attack vectors such as code injection in the client and thereby propagates a false sense of security to the enduser.  

The malleability of AES-CBC can effectively be prevented by using a
message authentication codec (MAC) preferably HMAC after encryption and
verifying it prior to decryption. Although this would effectively fix the
flaw however I would propose using a mode of operation with built-in
authentication such as GCM instead or better not using AES at all. How
this be can be done in a simple manner I will explain later in this
write-up.

One fun thing about this implementation error is that as before there's
a comment in the source code that actually points out to this exact
problem - at least partially. It seems the responsible coders just
forgot about that fact during implementation.

IV generation and reusage
-------------------------

While literature steadily recommends to generate the IV randomly each
time there is also commonly suggested to derive the IV using a PBKDF
from the encryption key on devices with low entropy. Exactely this is what is done in the Seafile
code. While there is nothing funtamentally wrong with this approach, if
possible this should be avoided if not absolutely necessarily - for
example memory limitations or a lack of randomness/entropy both common
on embedded devices - as it introduces an unnecessary constraint between
user/attacker controlled input and the initialisation vector which in
turn can lead to further attacks under certain circumstances. In AES-CBC
the initialization vector is combined with the first plaintext block.
Because of the porperties of AES-CBC (Each encrypted block is XORed with
the previous plain text block) it is then carried on block by block up to the last one. Depending on how it is derived from the encryption
key this can have a huge impact on the crypto scheme's security. For
example if the XOR combination is used as a part of the deriving
function this could lead to the encryption key and the IV ruling out
each other making the encryption completely effectless. (Evtl. DES weak
keys als Beispiel) In general it's a good rule of thumb to generate
everythig you can generate randomly randomly to avoid unforeseen
consequences. Since we have great CSPRNGS such as Salsa20 today which
don't require high entropy to produce pseudrandom output it's generally
prefered to use such an CSPRNG in combination with low entropy to
generate the IV.

IVs are used to prevent one of the most common attacks on ciphers in
general: The known plaintext attack. If the attacker either knows parts
of the plaintext corresponding to a cipher text or has access to an
encryption oracle this can be used to reconstruct ciphertexts or keys
completely. One prominent example - probably one of the most prominent
examples for practical attacks on cryptography in general - is the
decryption of the German's Enigma by the team around Alan Turing during
WWII. [citation needed] While reusing an IV in combination with a different encryption key
doesn't pose a problem, if reused with the same encryption key each time
a new ciphertext can be observed more details about the key respectively
the message contents are leaked to the attacker. [citation needed] This is especially
sensitive when it comes to file encryption since files always have known
portions. If the attacker is aware of the file type - which is the case for Seafile because it neglects meta data encryption - he will
also be aware of parts of its contents such as parts of the file header. Since Seafile
uses a static encryption key per file this poses a serious problem for
the security of the software.

Another problem with this that after each encryption the file will share the prefix with its previous version right up to the position of the changed
part. Furthermore a delta between the first block of the changed portion
and the first block of the current version can be calculated. Therefor
the attacker gains information about in which position the file has been
modified and \"how much\" the first block of the modified part has
changed. If one can observe a certain number of modifications this can
lead to complete compromise. [citation needed - libsodium docs]

The obvious fix for all problems mentioned above in this section is to
generate the IV or encryption key randomly for each encryption.

AES-CBC in combination with #PKCS7 padding
------------------------------------------
Yet to come.


Insecure handling of cryptographic keys
---------------------------------------

Since references to cryptographic keys are never forcefully deleted the
deletion from memory is completely left to the carbage collector of
Java. This means the keys remain on the programs stack for a very long
time in some circumstances. If an attacker manages to read out the
programms memory in some way he can simply recover the encryption keys
in the worst case.

The obvious solution to this is to forcefully delete references when the
key isn't used anymore by setting the variables value to NULL and then
manually instruct the JVM to run the garbage collection function
afterwords. This flaw only applies to the Java client but can be
implemented for the other programming languages used - such as Python
for the desktop client or Objective C for iOS - in a similar manner.

Proposal: A simple fix for everything
=====================================

As a that simple solution for all implementation errors mentioned above
I'd recommand to replace the whole implementation - that is replaceing
the seafile encrypt and decrypt methods - with libsodiums cryptobox
primitive. Because cryptobox encrypt/decrypt function expect the same
paramters as seafile encrypt/decrypt functions the source code must only
be slightly modified to introduce this change, libsodium is available
for all platforms and it is designed to prevent the implementor from all
mentioned attacks and furthermore uses the sidechannel resistant
streamcipher XSalsa20 for encryption/decryption and authentication. Not
only that there are currently no known feasable attacks against
XSalsa20, it also was implemnted with timing based sidechannel attacks
in mind by using only operations that take roughly the same time (with
neglectible differences) for encryption and decryption. In opposite to
AES-CBC wich has been known to be vulnerable to timing attacks for a
long time, it's simplicity makes it easy to audit and prevents problems
from beeing hidden inside a complex algorithm. Not only the
encryption/decryption algorithm by itself is dead simple it also uses
the same function for encryption and decryption and thereby further
minimizes the attack surface and simplifies peer reviewing. Also one of
the design goals are simplicity and easy understandability in order to
make it easy to audit and reduce the attack surface to the smallest
possible size. Furthermore it's the only peer reviewed cipher currently
available to the public that wasn't developed under influence of
govermeental organizations but by one of the currently most respected
cryptographers, Daniel Bernstein. Another huge advantage of the Salsa
family of ciphers is that they don't require hardware acceleration.
While slightly slower than AES on devices with integrated hardware
acceleration it has proven really fast even on old devices lacking
computing power and so is perfect for file syncronization software such
as Seafile.

Cryptobox not only handles proper encryption and decryption, it also
handles authentication in one pass and prevents all mentioned
implemention errors from happening by design. I want to point out that
I'm not affiliated with the developers of Salsa and libsodium
respectively and this is not an approach to do marketing.

Conclusion
==========

Yet to come.

*Best regards, Jakob Schindele, with help by Alina Platzer*
*Please note that this report is still under construction and therethore probably contains some errors*
*So don't hesitate to open an issue*
