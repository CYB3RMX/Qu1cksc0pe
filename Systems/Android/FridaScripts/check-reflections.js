Java.perform(function() {

    //var internalClasses = []; // uncomment this if you want no filtering!

    var internalClasses = ["android.", "com.android", "java.lang", "java.io"]; // comment this for no filtering

    var classDef = Java.use('java.lang.Class');

    var classLoaderDef = Java.use('java.lang.ClassLoader');

    var forName = classDef.forName.overload('java.lang.String', 'boolean', 'java.lang.ClassLoader');

    var loadClass = classLoaderDef.loadClass.overload('java.lang.String', 'boolean');

    var getMethod = classDef.getMethod.overload('java.lang.String', '[Ljava.lang.Object;');

    getMethod.implementation = function(a, b) {
        var method = getMethod.call(this, a, b);
        send("Reflection => getMethod => " + a + " => " + method.toGenericString());
        return method;
    }

    forName.implementation = function(class_name, flag, class_loader) {
        var isGood = true;
        for (var i = 0; i < internalClasses.length; i++) {
            if (class_name.startsWith(internalClasses[i])) {
                isGood = false;
            }
        }
        if (isGood) {
            send("Reflection => forName => " + class_name);
        }
        return forName.call(this, class_name, flag, class_loader);
    }

    loadClass.implementation = function(class_name, resolve) {
        var isGood = true;
        for (var i = 0; i < internalClasses.length; i++) {
            if (class_name.startsWith(internalClasses[i])) {
                isGood = false;
            }
        }
        if (isGood) {
            send("Reflection => loadClass => " + class_name);
        }
        return loadClass.call(this, class_name, resolve);
    }
});