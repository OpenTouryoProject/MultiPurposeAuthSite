import 'importer.dart';

// WebAPI呼出
import 'package:http/http.dart' as http;

// プッシュ通知
import 'package:firebase_messaging/firebase_messaging.dart';

// ...
import 'package:authentication_device/models/message_arguments.dart';

/// Displays information about a [RemoteMessage].
class MessageView extends StatelessWidget {

  /// A single data row.
  Widget _row(String? title, String? value, [double leftPadding = 0]) {
    if(30 < value!.length)
      value = value.substring(0, 30) + "...";

    return Padding(
      padding: EdgeInsets.only(
          left: 8 + leftPadding, right: 8, top: 8),
      child: Row(children: [
        Text('$title: '),
        Text(value ?? 'N/A'),
      ]),
    );
  }

  /// Push Ciba Result
  void _pushCibaResultApi(bool result, RemoteMessage? message) async {
    var response = await http.post(
      Uri.parse(AppAuth.cibaPushResultEndpoint),
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": "Bearer ${AppAuth.accessToken}",
      },
      body: {
        "auth_req_id" : message?.data["auth_req_id"],
        "result" : result.toString(),
      });

    if (response.statusCode == 200) {
    } else {
      print('Request failed with status: ${response.statusCode}.');
    }
  }

  @override
  Widget build(BuildContext context) {
    MessageArguments? args =
      ModalRoute.of(context)?.settings.arguments as MessageArguments;

    RemoteMessage? message = args.message;
    RemoteNotification? notification = message.notification;

    return Scaffold(
      appBar: AppBar(
        title: Text(notification?.title ?? ""),
      ),
      body: SingleChildScrollView(
        child: Padding(
          padding: const EdgeInsets.all(8),
          child: Column(children: [
            this._row('Sent Time', message.sentTime?.toString() ?? ""),
            if (notification != null) ...[
              Padding(
                padding: const EdgeInsets.only(top: 16),
                child: Column(children: [
                  const Text(
                    'Remote Notification',
                    style: TextStyle(fontSize: 18),
                  ),
                  this._row(
                    'Title',
                    notification.title ?? "",
                  ),
                  this._row(
                    'Body',
                    notification.body ?? "",
                  )
                ]),
              )
            ],
            if(notification?.title == "CIBA") ...[
              Padding(
                padding: const EdgeInsets.only(top: 16),
                child: Column(children: [
                  const Text(
                    'Remote Notification Data',
                    style: TextStyle(fontSize: 18),
                  ),
                  this._row('Data', message.data.keys.toString()),
                  this._row('binding_message', message.data["binding_message"], 12),
                  this._row('auth_req_id', message.data["auth_req_id"], 12),
                  SpaceBox.height(16),
                  Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      MyElevatedButton('Allow Button', () => {
                        this._pushCibaResultApi(true, message)
                      }),
                      SpaceBox.width(16),
                      MyElevatedButton('Deny Button', () => {
                        this._pushCibaResultApi(false, message)
                      }),
                    ]
                  ),
                ]),
              )
            ]
          ]),
        )
      ),
    );
  }
}