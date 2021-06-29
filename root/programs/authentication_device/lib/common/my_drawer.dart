/// 画面に表示される左メニュー（Drawer）。

import 'package:flutter/material.dart';

class MyDrawer extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Drawer(
      child: ListView(
        children: <Widget>[
          DrawerHeader(
            child: Text('Drawer Header'),
            decoration: BoxDecoration(
              color: Colors.blue,
            ),
          ),
          ListTile(
            title: Text("root"),
            trailing: Icon(Icons.arrow_forward),
            onTap: () {
              while(Navigator.of(context).canPop()){
                Navigator.of(context).pop();
              }
            },
          ),
          ListTile(
            title: Text("appauth"),
            trailing: Icon(Icons.arrow_forward),
            onTap: () {
              while(Navigator.of(context).canPop()){
                Navigator.of(context).pop();
              }
              Navigator.of(context).pushNamed("/appauth");
            },
          ),
          ListTile(
            title: Text("fcm"),
            trailing: Icon(Icons.arrow_forward),
            onTap: () {
              while(Navigator.of(context).canPop()){
                Navigator.of(context).pop();
              }
              Navigator.of(context).pushNamed("/fcm");
            },
          ),
          ListTile(
            title: Text("gyomu"),
            trailing: Icon(Icons.arrow_forward),
            onTap: () {
              while(Navigator.of(context).canPop()){
                Navigator.of(context).pop();
              }
              Navigator.of(context).pushNamed("/gyomu");
            },
          ),
          ListTile(
            title: Text("crud"),
            trailing: Icon(Icons.arrow_forward),
            onTap: () {
              while(Navigator.of(context).canPop()){
                Navigator.of(context).pop();
              }
              Navigator.of(context).pushNamed("/crud");
            },
          ),
        ],
      ),
    );
  }
}