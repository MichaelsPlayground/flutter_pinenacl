import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:pinenacl/api.dart';
import 'package:pinenacl/x25519.dart' show Box, PrivateKey, EncryptedMessage, SecretBox, SealedBox;
import 'package:pinenacl/ed25519.dart';
import 'package:pinenacl/src/digests/digests.dart';
import 'package:pinenacl/tweetnacl.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({Key? key}) : super(key: key);

  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter PineNacl Demo',
      theme: ThemeData(
        // This is the theme of your application.
        //
        // Try running your application with "flutter run". You'll see the
        // application has a blue toolbar. Then, without quitting the app, try
        // changing the primarySwatch below to Colors.green and then invoke
        // "hot reload" (press "r" in the console where you ran "flutter run",
        // or simply save your changes to "hot reload" in a Flutter IDE).
        // Notice that the counter didn't reset back to zero; the application
        // is not restarted.
        primarySwatch: Colors.blue,
      ),
      home: const MyHomePage(title: 'Flutter PineNacl Demo'),
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({Key? key, required this.title}) : super(key: key);

  // This widget is the home page of your application. It is stateful, meaning
  // that it has a State object (defined below) that contains fields that affect
  // how it looks.

  // This class is the configuration for the state. It holds the values (in this
  // case the title) provided by the parent (in this case the App widget) and
  // used by the build method of the State. Fields in a Widget subclass are
  // always marked "final".

  final String title;

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  int _counter = 0;

  void _incrementCounter() {
    setState(() {
      // This call to setState tells the Flutter framework that something has
      // changed in this State, which causes it to rerun the build method below
      // so that the display can reflect the updated values. If we changed
      // _counter without calling setState(), then the build method would not be
      // called again, and so nothing would appear to happen.
      _counter++;
    });
  }

  void _run_pinenacl_hashing() {
    const hex = HexCoder.instance;

    print('\n### Hashing - Blake2b Example ###\n');

    final hasher = Hash.blake2b;

    /// # Hashing
    print('Hash example\nH(\'\'): ${hex.encode(hasher(''))}');

    /// # Message authentication
    /// To authenticate a message, using a secret key, the blake2b function must be called as in the following example.
    print('\nMessage authentication');

    /// Message authentication example
    /// It can ganarate a MAC to be sure that the message is not forged.
    final msg = '256 BytesMessage' * 16;

    // the simplest way to get a cryptographic quality authKey
    // is to generate it with a cryptographic quality
    // random number generator
    final authKey = PineNaClUtils.randombytes(64);
    final mac = hasher(msg, key: authKey);

    print('MAC(msg, authKey): ${hex.encode(mac)}.\n');

    /// # Key derivation example
    /// The blake2b algorithm can replace a key derivation function by following the lines of:
    print('Key derivation example');
    final masterKey = PineNaClUtils.randombytes(64);
    final derivationSalt = PineNaClUtils.randombytes(16);

    final personalisation = Uint8List.fromList('<DK usage>'.codeUnits);

    final subKey = hasher('',
        key: masterKey, salt: derivationSalt, personalisation: personalisation);
    print('KDF(\'\', masterKey, salt, personalisation): ${hex.encode(subKey)}');

    /// By repeating the key derivation procedure before encrypting our messages,
    /// and sending the derivationSalt along with the encrypted message, we can expect to never reuse a key,
    /// drastically reducing the risks which ensue from such a reuse.
    /// SHA-256 Example.
    print('\nSHA-256 Example.\n');
    var message =
        '01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789';
    final out = Hash.sha256(Uint8List.fromList(message.codeUnits));
    print('Resulted: ${hex.encode(out)}');
    print(
        'Expected: 3935959adc03ef044edba6e0c69dc7322e34668c2ca74470e4d39f20362b977a');

    final macOut = Uint8List(64);
    final k = List<int>.generate(128, (i) => i).toUint8List();
    final text =
    Uint8List.fromList('Sample message for keylen=blocklen'.codeUnits);

    TweetNaClExt.crypto_auth_hmacsha256(macOut, text, k);
    print('MAC 256: ${hex.encode(macOut)}');

    TweetNaClExt.crypto_auth_hmacsha512(macOut, text, k);
    print('MAC 512: ${hex.encode(macOut)}');
  }

  void _run_pinenacl_signature() {
    const hex = HexCoder.instance;
    print('\n### Digital Signatures - Signing Example ###\n');

    /// Signer’s perspective (SigningKey)
    //final signingKey = SigningKey.generate();
    const seed =
        '19a91fe23a4e9e33ecc474878f57c64cf154b394203487a7035e1ad9cd697b0d';
    const publ =
        '2bf32ba142ba4622d8f3e29ecd85eea07b9c47be9d64412c9b510b27dd218b23';

    const mesg = '82cb53c4d5a013bae5070759ec06c3c6955ab7a4050958ec328c';
    const sigd =
        '881f5b8c5a030df0f75b6634b070dd27bd1ee3c08738ae349338b3ee6469bbf9760b13578a237d5182535ede121283027a90b5f865d63a6537dca07b44049a0f82cb53c4d5a013bae5070759ec06c3c6955ab7a4050958ec328c';

    final signingKey = SigningKey(seed: hex.decode(seed));
    final verifyKey = signingKey.verifyKey;
    final publicKey = VerifyKey(hex.decode(publ));
    assert(publicKey == verifyKey);
    print('Verify Key: ${hex.encode(verifyKey)}');

    final signed = signingKey.sign(hex.decode(mesg));
    final encoded = hex.encode(signed);

    print(encoded);
    assert(sigd == encoded);
    //  Obtain the verify key for a given signing key

    // Serialize the verify key to send it to a third party
    final verifyKeyHex = verifyKey.encode(hex);

    ///
    /// Verifier’s perspective (VerifyKey)
    ///
    final verifyKey2 = VerifyKey.decode(verifyKeyHex, coder: hex);
    assert(verifyKey == verifyKey2);

    // Check the validity of a message's signature
    // The message and the signature can either be passed separately or
    // concatenated together.  These are equivalent:
    var isVerified = verifyKey.verifySignedMessage(signedMessage: signed);
    isVerified &= verifyKey.verify(
        signature: signed.signature, message: signed.message.asTypedList);

    final resString = isVerified ? '' : 'UN';
    print('Verification of the signature was: ${resString}SUCCESSFULL ');
  }

  void _run_pinenacl_secretbox(){
    print('\n### Secret Key Encryption - SecretBox Example ###\n');
    final key = PineNaClUtils.randombytes(SecretBox.keyLength);
    final box = SecretBox(key);
    final message =
        'Change is a tricky thing, it threatens what we find familiar with...';

    final encrypted = box.encrypt(Uint8List.fromList(message.codeUnits));
    final decrypted = box.decrypt(encrypted);
    final ctext = encrypted.cipherText;
    assert(ctext.length == message.length + SecretBox.macBytes);
    final plaintext = String.fromCharCodes(decrypted);
    print(plaintext);
    assert(message == plaintext);
  }

  void _run_pinenacl_sealedbox() {
    print('\n### Public Key Encryption - SealedBox Example ###\n');
    // Generate Bob's private key, which must be kept secret
    final skbob = PrivateKey.generate();
    final pkbob = skbob.publicKey;
    // Alice wishes to send a encrypted message to Bob,
    // but prefers the message to be untraceable
    // she puts it into a secretbox and seals it.
    final sealedBox = SealedBox(pkbob);

    final message = 'The world is changing around us and we can either get '
        'with the change or we can try to resist it';

    final encrypted = sealedBox.encrypt(message.codeUnits.toUint8List());
    try {
      sealedBox.decrypt(encrypted);
    } on Exception catch (e) {
      print('Exception\'s successfully cought:\n$e');
    }
    // Bob unseals the box with his privatekey, and decrypts it.
    final unsealedBox = SealedBox(skbob);
    final plainText = unsealedBox.decrypt(encrypted);
    print(String.fromCharCodes(plainText));
    assert(message == String.fromCharCodes(plainText));
  }

  void _run_pinenacl_box() {
    // box example
    print('\n### Public Key Encryption - Box Example ###\n');
    // Generate Bob's private key, which must be kept secret
    final skbob = PrivateKey.generate();

    // Bob's public key can be given to anyone wishing to send
    // Bob an encrypted message
    final pkbob = skbob.publicKey;

    // Alice does the same and then Alice and Bob exchange public keys
    final skalice = PrivateKey.generate();

    final pkalice = skalice.publicKey;

    // Bob wishes to send Alice an encrypted message so Bob must make a Box with
    // his private key and Alice's public key
    final bobBox = Box(myPrivateKey: skbob, theirPublicKey: pkalice);

    // This is our message to send, it must be a bytestring as Box will treat it
    // as just a binary blob of data.
    final message =
        'There is no conspiracy out there, but lack of the incentives to drive the people towards the answers.';

    // TweetNaCl can automatically generate a random nonce for us, making the encryption very simple:
    // Encrypt our message, it will be exactly 40 bytes longer than the
    // original message as it stores authentication information and the
    // nonce alongside it.
    final encryptedAsList =
    bobBox.encrypt(Uint8List.fromList(message.codeUnits)).sublist(0);

    print('encryptedAsList:' + base64Encode(encryptedAsList));
    // Finally, the message is decrypted (regardless of how the nonce was generated):
    // Alice creates a second box with her private key to decrypt the message
    final aliceBox = Box(myPrivateKey: skalice, theirPublicKey: pkbob);

    // Decrypt our message, an exception will be raised if the encryption was
    // tampered with or there was otherwise an error.
    final decrypted =
    aliceBox.decrypt(EncryptedMessage.fromList(encryptedAsList.asTypedList));
    print(String.fromCharCodes(decrypted));
  }

  @override
  Widget build(BuildContext context) {
    // This method is rerun every time setState is called, for instance as done
    // by the _incrementCounter method above.
    //
    // The Flutter framework has been optimized to make rerunning build methods
    // fast, so that you can just rebuild anything that needs updating rather
    // than having to individually change instances of widgets.
    return Scaffold(
      appBar: AppBar(
        // Here we take the value from the MyHomePage object that was created by
        // the App.build method, and use it to set our appbar title.
        title: Text(widget.title),
      ),
      body: Center(
        // Center is a layout widget. It takes a single child and positions it
        // in the middle of the parent.
        child: Column(
          // Column is also a layout widget. It takes a list of children and
          // arranges them vertically. By default, it sizes itself to fit its
          // children horizontally, and tries to be as tall as its parent.
          //
          // Invoke "debug painting" (press "p" in the console, choose the
          // "Toggle Debug Paint" action from the Flutter Inspector in Android
          // Studio, or the "Toggle Debug Paint" command in Visual Studio Code)
          // to see the wireframe for each widget.
          //
          // Column has various properties to control how it sizes itself and
          // how it positions its children. Here we use mainAxisAlignment to
          // center the children vertically; the main axis here is the vertical
          // axis because Columns are vertical (the cross axis would be
          // horizontal).
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            const Text(
              'You have pushed the button this many times:',
            ),
            Text(
              '$_counter',
              style: Theme.of(context).textTheme.headline4,
            ),
          ],
        ),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: () {
          _incrementCounter;
          _run_pinenacl_box();
          _run_pinenacl_secretbox();
          _run_pinenacl_sealedbox();
          _run_pinenacl_signature();
          _run_pinenacl_hashing();
        },
        tooltip: 'Increment',
        child: const Icon(Icons.add),
      ), // This trailing comma makes auto-formatting nicer for build methods.
    );
  }
}
