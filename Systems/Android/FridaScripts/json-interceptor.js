console.log("[+] loading -------JSON object interceptor-------+\n")

var jsonLogger = Java.use('org.json.JSONObject');
var stringClass = Java.use("java.lang.String");

jsonLogger.put.overload('java.lang.String', 'java.lang.Object').implementation = function(key,value){
    console.log('\n->->->->->->->->->->->->->->->->->->->->->->->->->->->');
    console.log('App is creating a json object with the following data:');
    console.log('Key: ' +key+ ' Value: ' + value);
    return this.put(key,value);
}
jsonLogger.optString.overload('java.lang.String').implementation = function(name){
    console.log('\n<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-');
    console.log('App is receiving a json object with the following data:');
    console.log('Key: ' +name+ ' Value: ' + this.optString(name));
    return this.optString(name);
}

jsonLogger.optString.overload('java.lang.String','java.lang.String').implementation = function(name,value){
    console.log('\n<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-');
    console.log('App is receiving a json object with the following data:');
    console.log('Key: ' +name+ ' Value: ' + value + ' output: ' + this.optString(name,value));
    return this.optString(name,value);
}
console.log("[+] loaded -------JSON object interceptor-------+")
