Here the example of all method, enjoy coding 😃

```dart
import 'package:auth_totp/auth_totp.dart';
import 'package:flutter/material.dart';

void main() {
  runApp(
    const MaterialApp(
      debugShowCheckedModeBanner: false,
      home: QRCodePage(),
    ),
  );
}

class QRCodePage extends StatefulWidget {
  const QRCodePage({super.key});

  @override
  State<QRCodePage> createState() => _QRCodePageState();
}

class _QRCodePageState extends State<QRCodePage> {
  String secret = AuthTOTP.createSecret(
      length: 16,
      autoPadding: true,
      secretKeyStyle: SecretKeyStyle.upperLowerCase);
  String appName = "TOTP"; //Give your app name

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text("Auth TOTP Flutter Package",
            style: TextStyle(color: Colors.white)),
        centerTitle: true,
        backgroundColor: Colors.green,
        elevation: 0,
        shadowColor: Colors.transparent,
      ),
      body: ListView(
        padding: const EdgeInsets.all(16.0),
        children: [
          const Center(
            child: Text(
                "Scan this QR code or copy the secret code to your authenticator app. Click continue to verify."),
          ),
          Image.network(
              AuthTOTP.getQRCodeUrl(appName: appName, secretKey: secret)),
          Padding(
            padding: const EdgeInsets.all(8.0),
            child: TextField(
              controller: TextEditingController(text: secret),
              decoration: const InputDecoration(
                border: OutlineInputBorder(),
                labelText: 'Secret Code',
              ),
              readOnly: true,
            ),
          ),
          ElevatedButton(
            onPressed: () {
              Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (context) => VerificationPage(secret: secret),
                ),
              );
            },
            child: const Text("Continue to Verify"),
          ),
        ],
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: () {
          setState(() {
            secret = AuthTOTP.createSecret(
                length: 16,
                autoPadding: true,
                secretKeyStyle: SecretKeyStyle.upperLowerCase);
            ;
            print(AuthTOTP.generateTOTPCode(secretKey: secret, interval: 30));
          });
        },
        child: const Icon(Icons.refresh),
      ),
    );
  }
}

class VerificationPage extends StatefulWidget {
  final String secret;
  const VerificationPage({super.key, required this.secret});

  @override
  State<VerificationPage> createState() => _VerificationPageState();
}

class _VerificationPageState extends State<VerificationPage> {
  String code = "";

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text("Verify TOTP", style: TextStyle(color: Colors.white)),
        centerTitle: true,
        backgroundColor: Colors.green,
        elevation: 0,
        shadowColor: Colors.transparent,
      ),
      body: Center(
        child: ListView(
          padding: const EdgeInsets.all(16.0),
          children: [
            Padding(
              padding: const EdgeInsets.all(8.0),
              child: TextField(
                keyboardType: TextInputType.number,
                decoration: const InputDecoration(
                  border: OutlineInputBorder(),
                  labelText: 'Enter TOTP Code',
                ),
                onChanged: (value) {
                  setState(() {
                    code = value;
                  });
                },
              ),
            ),
            ElevatedButton(
              onPressed: () {
                setState(() {
                  if (AuthTOTP.verifyCode(
                      secretKey: widget.secret, totpCode: code)) {
                    ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
                      content: Text("Congratulations, TOTP is correct"),
                      backgroundColor: Colors.green,
                      behavior: SnackBarBehavior.floating,
                      margin: EdgeInsets.all(10),
                      shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.all(Radius.circular(10))),
                    ));
                  } else {
                    ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
                      content: Text("Opps, TOTP is incorrect"),
                      backgroundColor: Colors.red,
                      behavior: SnackBarBehavior.floating,
                      margin: EdgeInsets.all(10),
                      shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.all(Radius.circular(10))),
                    ));
                  }
                });
              },
              child: const Text("Verify"),
            ),
          ],
        ),
      ),
    );
  }
}

```
