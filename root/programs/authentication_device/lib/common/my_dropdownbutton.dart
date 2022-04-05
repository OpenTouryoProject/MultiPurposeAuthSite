/// カスタムのDropdownButton

import 'package:flutter/material.dart';

class MyDropdownButton extends StatelessWidget {

  final String _caption;
  final void Function(Object?)? _onChanged;

  String? _selectedKey = "";
  List<DropdownMenuItem<String>>? _items = [];

  MyDropdownButton(
      this._caption,
      this._onChanged,
      this._selectedKey,
      Map<String, String> items,
      {Key? key}) : super(key: key)
  {
    for(String key in items.keys) {
      this._items?.add(DropdownMenuItem(
        child: Text(key),
        value: items[key],
      ));
    }
  }

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.start,
      children: <Widget>[
        Container(
          margin: EdgeInsets.only(right: 10),
          child: Text(this._caption),
        ),
        DropdownButton<Object>(
          items: this._items,
          value: this._selectedKey,
          onChanged: this._onChanged,
        ),
      ],
    );
  }
}