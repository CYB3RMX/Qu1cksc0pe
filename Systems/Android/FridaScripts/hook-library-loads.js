Java.perform(function() {
    const System = Java.use('java.lang.System');
    const Runtime = Java.use('java.lang.Runtime');
    const VMStack = Java.use('dalvik.system.VMStack');

    System.loadLibrary.implementation = function(library) {
        try {
            console.log('System.loadLibrary("' + library + '")');
            Runtime.getRuntime().loadLibrary0(VMStack.getCallingClassLoader(), library);
        } catch(ex) {
            console.log(ex);
        }
    };
    
    System.load.implementation = function(library) {
        try {
            console.log('System.load("' + library + '")');
            Runtime.getRuntime().nativeLoad(library, VMStack.getCallingClassLoader());
        } catch(ex) {
            console.log(ex);
        }
    };
});
