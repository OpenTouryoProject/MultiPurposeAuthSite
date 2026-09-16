/// カスタムのElevatedButton

import 'package:flutter/material.dart';

class MyElevatedButton extends StatelessWidget {

  final String _caption;
  final VoidCallback _onPressed;

  const MyElevatedButton(
      this._caption, this._onPressed,
      {Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return ElevatedButton(
      child: Text(this._caption),
      style: ElevatedButton.styleFrom(
        backgroundColor: Colors.orange,
        foregroundColor: Colors.white,
      ),
      onPressed: this._onPressed,
    );
  }
}