import '../importer.dart';

// ...
import 'package:authentication_device/components/fcm_page/permissions.dart';
import 'package:authentication_device/components/fcm_page/message_list.dart';

class FcmPage extends StatefulWidget {
  FcmPage({Key? key, required this.title}) : super(key: key);

  final String title;

  @override
  _FcmPageState createState() => _FcmPageState();
}

class _FcmPageState extends State<FcmPage> {

  @override
  void initState() {
    super.initState();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(widget.title),
      ),
      body: SingleChildScrollView(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.spaceEvenly,
          children: <Widget>[
            Column(children: [
              MetaCard('Permissions', Permissions()),
              /*MetaCard('FCM Token', TokenChecker((token) {
                return token == null
                    ? const CircularProgressIndicator()
                    : Text(token, style: const TextStyle(fontSize: 12));
              })),*/
              MetaCard('Message Stream', MessageList()),
            ])
          ],
        ),
      ),
      drawer: MyDrawer(),
    );
  }
}