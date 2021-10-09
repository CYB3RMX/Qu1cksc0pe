console.log("\n[+] Intent sniffer starts...")
console.log("---------------------------------------------\n")

Java.perform(function () {
    var act = Java.use("android.app.Activity");
    act.getIntent.overload().implementation = function () {
      var intent = this.getIntent()
      var cp = intent.getComponent()
      console.log("Starting " + cp.getPackageName() + "/" + cp.getClassName())
      var ext = intent.getExtras();
      if (ext) {
        var keys = ext.keySet()
        var iterator = keys.iterator()
        while (iterator.hasNext()) {
          var k = iterator.next().toString()
          var v = ext.get(k)
          console.log("\t" + v.getClass().getName())
          console.log("\t" + k + ' : ' + v.toString())
        }
      }
    return intent;
    };
 })