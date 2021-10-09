/*
	Author: secretdiary.ninja
	License: (CC BY-SA 4.0) 
 * */
 
    setImmediate(function() {
        Java.perform(function() {
    
            var context = Java.use("android.app.ContextImpl");
    
            context.checkSelfPermission.overload('java.lang.String').implementation = function (var0) {
                console.log("[*] ContextImpl.checkSelfPermission called: " + var0 +"\n");			
                return this.checkSelfPermission;
            };
    
            var contextCompat = Java.use("android.support.v4.content.ContextCompat");
    
            contextCompat.checkSelfPermission.overload('android.content.Context', 'java.lang.String').implementation = function (var0, var1) {
                console.log("[*] ContextCompat.checkSelfPermission called: " + var1 +"\n");			
                return this.checkSelfPermission;
            };
    
            var permissionChecker = Java.use("android.support.v4.content.PermissionChecker");
    
            permissionChecker.checkSelfPermission.overload('android.content.Context', 'java.lang.String').implementation = function (var0, var1) {
                console.log("[*] PermissionChecker.checkSelfPermission called: " + var1 +"\n");			
                return this.checkSelfPermission;
            };
    
            var activityCompat = Java.use("android.support.v4.app.ActivityCompat");
    
            // void requestPermissions (Activity activity, String[] permissions, int requestCode)		
            activityCompat.requestPermissions.overload('android.app.Activity', '[Ljava.lang.String;', 'int').implementation = function (var0, var1, var2) {
                console.log("[*] ActivityCompat.requestPermissions called. Permissions: " + var1 +"\n");
                this.requestPermissions(var0, var1, var2);	
            }
        });
    });