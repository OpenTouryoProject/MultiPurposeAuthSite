import 'importer.dart';

// WebAPI呼出
import 'package:http/http.dart' as http;

class CrudPage extends StatefulWidget {
  CrudPage({Key? key, required this.title}) : super(key: key);

  final String title;

  @override
  _CrudPageState createState() => _CrudPageState();
}

class _CrudPageState extends State<CrudPage> {
  // ddl値
  String _ddlDap = "SQL";
  String _ddlMode1 = "individual";
  String _ddlMode2 = "static";
  String _ddlIso = "RC";
  String _ddlExRollback = "-";
  String _orderColumn = "c1";
  String _orderSequence = "";

  // 値取得
  final _formKey = GlobalKey<FormState>();
  // 値設定
  final _shipperIDKey = GlobalKey<FormFieldState>();
  final _companyNameKey = GlobalKey<FormFieldState>();
  final _phoneKey = GlobalKey<FormFieldState>();
  // Field値
  String _shipperID = "";
  String _companyName = "";
  String _phone = "";
  // フォーカス制御
  final _shipperIDFocusNode = FocusNode();
  final _companyNameFocusNode = FocusNode();
  final _phoneFocusNode = FocusNode();

  // JSON値
  String _display = "";
  List<dynamic> _jsonItems  = jsonDecode(
      '[{"shipperID":"shipperID","companyName":"companyName","phone":"phone"}]'
  );

  @override
  void initState() {
    super.initState();
  }

  Future<void> _selectCount() async {
    print("accessToken: " + AppAuth.accessToken!);
    var url = Uri.http(AppConfig.serverFqdn,
      'ASPNETWebService/api/json/SelectCount',);
    var response = await http.post(url,
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": "Bearer ${AppAuth.accessToken}",
      },
      body: {
        "ddlDap" : this._ddlDap,
        "ddlMode1" : this._ddlMode1,
        "ddlMode2": this._ddlMode2,
        "ddlExRollback" : this._ddlExRollback,
      }
    );
    if (response.statusCode == 200) {
      Map<String, dynamic> jsonResponse
        = jsonDecode(response.body) as Map<String, dynamic>;
      setState(() {
        this._display = jsonResponse['message'];
      });
    } else {
      print('Request failed with status: ${response.statusCode}.');
    }
  }

  Future<void> _selectAll(String urlPrefix) async {
    var url = Uri.http(AppConfig.serverFqdn,
        'ASPNETWebService/api/json/SelectAll_' + urlPrefix);
    var response = await http.post(url,
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": "Bearer ${AppAuth.accessToken}",
      },
      body: {
        "ddlDap" : this._ddlDap,
        "ddlMode1" : this._ddlMode1,
        "ddlMode2": this._ddlMode2,
        "ddlExRollback" : this._ddlExRollback,
        "orderColumn" : this._orderColumn,
        "orderSequence" : this._orderSequence,
      }
    );
    if (response.statusCode == 200) {
      Map<String, dynamic> jsonResponse
        = jsonDecode(response.body) as Map<String, dynamic>;
      setState(() {
        this._display = jsonResponse['message'];
        this._jsonItems = jsonResponse['result'];
      });
    } else {
      print('Request failed with status: ${response.statusCode}.');
    }
  }

  Future<void> _crud(String urlPrefix) async {
    this._formKey.currentState?.save();

    var url = Uri.http(AppConfig.serverFqdn,
        'ASPNETWebService/api/json/' + urlPrefix);
    var response = await http.post(url,
        headers: {
          "Accept": "application/json",
          "Content-Type": "application/json",
          "Authorization": "Bearer ${AppAuth.accessToken}",
        },
        body: jsonEncode({
          "ddlDap" : this._ddlDap,
          "ddlMode1" : this._ddlMode1,
          "ddlMode2": this._ddlMode2,
          "ddlExRollback" : this._ddlExRollback,
          "shipper": {
            "shipperID": this._shipperID,
            "companyName": this._companyName,
            "phone": this._phone
          }
        }),
    );
    if (response.statusCode == 200) {
      Map<String, dynamic>? jsonResponse = null;
      jsonResponse = jsonDecode(response.body) as Map<String, dynamic>;
      setState(() {
        this._display = jsonResponse?['message'];
        if(urlPrefix == "Select") {
          var shipper = jsonResponse?['result'];
          this._shipperIDKey.currentState?.didChange(shipper['shipperID']);
          this._companyNameKey.currentState?.didChange(shipper['companyName']);
          this._phoneKey.currentState?.didChange(shipper['phone']);
        }
      });
    } else {
      print('Request failed with status: ${response.statusCode}.');
    }
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
            MyDropdownButton(
              "ddlDap",
              (value) => {
                setState(() {
                  this._ddlDap = value.toString();
                }),
              },
              this._ddlDap,
              {
                "SQL Server / SQL Client" : "SQL",
                "Multi-DB / OLEDB.NET" : "OLE",
                "Multi-DB / ODBC.NET" : "ODB",
                "Oracle / ODP.NET" : "ODP",
                "DB2 / DB2.NET" : "DB2",
                "HiRDB / HiRDB-DP" : "HIR",
                "MySQL Cnn/NET" : "MCN",
                "PostgreSQL / Npgsql" : "NPS"
              }
            ),
            MyDropdownButton(
              "ddlMode1",
              (value) => {
                setState(() {
                  this._ddlMode1 = value.toString();
                }),
              },
              this._ddlMode1,
              {
                "個別Ｄａｏ" : "individual",
                "共通Ｄａｏ" : "common",
                "自動生成Ｄａｏ（更新のみ）" : "generate",
              }
            ),
            MyDropdownButton(
              "ddlMode2",
                (value) => {
                  setState(() {
                    this._ddlMode2 = value.toString();
                }),
              },
              this._ddlMode2,
              {
                "静的クエリ" : "static",
                "動的クエリ" : "dynamic",
              }
            ),
            MyDropdownButton(
              "ddlIso",
              (value) => {
                setState(() {
                  this._ddlIso = value.toString();
                }),
              },
              this._ddlIso,
              {
                "ノットコネクト" : "NC",
                "ノートランザクション" : "NT",
                "ダーティリード" : "RU",
                "リードコミット" : "RC",
                "リピータブルリード" : "RR",
                "シリアライザブル" : "SZ",
                "スナップショット" : "SS",
                "デフォルト" : "DF",
              }
            ),
            MyDropdownButton(
              "ddlExRollback",
              (value) => {
                setState(() {
                  this._ddlExRollback = value.toString();
                }),
              },
              this._ddlExRollback,
              {
                "正常時" : "-",
                "業務例外" : "Business",
                "システム例外" : "System",
                "その他、一般的な例外" : "Other",
                "業務例外への振替" : "Other-Business",
                "システム例外への振替" : "Other-System",
              }
            ),
            MyDropdownButton(
              "ddlOrder",
              (value) => {
                setState(() {
                  this._orderColumn = value.toString();
                }),
              },
              this._orderColumn,
              {
                "c1" : "c1",
                "c2" : "c2",
                "c3" : "c3",
              }
            ),
            MyDropdownButton(
              "ddlOrderSequence",
              (value) => {
                setState(() {
                  this._orderSequence = value.toString();
                }),
              },
              this._orderSequence,
              {
                "ASC" : "",
                "DESC" : "D",
              }
            ),
            Form(
              key: this._formKey,
              child: Column(
                children: [
                  TextFormField(
                    key: this._shipperIDKey,
                    decoration: InputDecoration(labelText: 'shipperID'),
                    textInputAction: TextInputAction.next,
                    onFieldSubmitted: (_) {
                      FocusScope.of(context).requestFocus(this._companyNameFocusNode);
                    },
                    onSaved: (value) {
                      this._shipperID = value ?? "";
                    },
                  ),
                  TextFormField(
                    key: this._companyNameKey,
                    decoration: InputDecoration(labelText: 'companyName'),
                    textInputAction: TextInputAction.next,
                    focusNode: this._companyNameFocusNode,
                    onFieldSubmitted: (_) {
                      FocusScope.of(context).requestFocus(this._companyNameFocusNode);
                    },
                    onSaved: (value) {
                      this._companyName = value ?? "";
                    },
                  ),
                  TextFormField(
                    key: this._phoneKey,
                    decoration: InputDecoration(labelText: 'phone'),
                    focusNode: this._phoneFocusNode,
                    onSaved: (value) {
                      this._phone = value ?? "";
                    },
                  ),
                ],
              ),
            ),
            Row(
                mainAxisAlignment: MainAxisAlignment.spaceAround,
                children: <Widget>[
                  MyElevatedButton('Select', (){ this._crud("Select"); }),
                  MyElevatedButton('Insert', (){ this._crud("Insert"); }),
                  MyElevatedButton('Update', (){ this._crud("Update"); }),
                  MyElevatedButton('Delete', (){ this._crud("Delete"); }),
                ]
            ),
            Row(
                mainAxisAlignment: MainAxisAlignment.spaceAround,
                children: <Widget>[
                  MyElevatedButton('SelectCount', this._selectCount),
                  MyElevatedButton('SelectAll_DT', (){ this._selectAll("DT"); }),
                  MyElevatedButton('SelectAll_DSQL', (){ this._selectAll("DSQL"); }),
                ]
            ),
            Column(
              mainAxisAlignment: MainAxisAlignment.spaceEvenly,
              children: <Widget>[
                Column(
                  crossAxisAlignment: CrossAxisAlignment.center,
                  children: <Widget>[
                    Text(
                      '件数:',
                    ),
                    Text(
                      this._display,
                      style: Theme.of(context).textTheme.headline4,
                    ),
                  ],
                ),
                DataTable(
                  columns: [
                    DataColumn(label: Text('shipperID')),
                    DataColumn(label: Text('companyName')),
                    DataColumn(label: Text('phone')),
                  ],
                  rows: (this._jsonItems).map((element) => DataRow(
                    cells: <DataCell>[
                      DataCell(Text(element["shipperID"] ?? "")),
                      DataCell(Text(element["companyName"] ?? "")),
                      DataCell(Text(element["phone"] ?? "")),
                    ]
                  )).toList(),
                ),
              ]
            ),
          ],
        )
      ),
      drawer: MyDrawer(),
    );
  }
}