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
            title: Text("top"),
            trailing: Icon(Icons.arrow_forward),
            onTap: () {
              while(Navigator.of(context).canPop()){
                Navigator.of(context).pop();
              }
            },
          ),
          ListTile(
            title: Text("mypage"),
            trailing: Icon(Icons.arrow_forward),
            onTap: () {
              while(Navigator.of(context).canPop()){
                Navigator.of(context).pop();
              }
              Navigator.of(context).pushNamed("/mypage");
            },
          ),
        ],
      ),
    );
  }
}