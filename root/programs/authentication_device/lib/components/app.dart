import 'package:authentication_device/components/gyomu_page.dart';

import 'importer.dart';

class MyApp extends StatelessWidget {
  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter Demo',
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
      routes: {
        '/': (context) => MyHomePage(title: 'Flutter Demo Home Page'),
        '/appauth': (context) => AppAuthPage(title: 'Flutter Demo AppAuth Page'),
        '/fcm': (context) => FcmPage(title: 'Flutter Demo FCM Page'),
        '/gyomu': (context) => GyomuPage(title: 'Flutter Demo Gyomu Page'),
        '/crud': (context) => CrudPage(title: 'Flutter Demo CRUD Page'),
        '/message': (context) => MessageView(),
      },
    );
  }
}