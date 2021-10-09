/*
 * Android Broadcast Receiver
 *
 * Usage: frida -U --codeshare leolashkevych/android-broadcast-receiver com.android.systemui
 *
 * 1. Registering a broadcast receiver with a specified intent filter:
 *
 *     registerReceiver(IntentFilter);
 *     registerReceiver('com.example.customAction');
 *
 * 2. Registering a "catch all" broadcast receiver:
 * Android SDK does not allow the registration of a receiver without specifying an intent filter
 * and does not support wildcard filters. This restriction can be circumvented using Java's
 * reflection features to enumerate all applicable events. Then a custom receiver can be
 * registered for each event type. The limitation of this method is the inability to catch
 * non-standard actions/categories/extras. In such cases, use "registerReceiver(IntentFilter);".
 *
 *     registerReceiverForAll();
 *
 * 3. Hook an existing broadcast receiver:
 *
 *   frida -U --codeshare leolashkevych/android-broadcast-receiver -f com.application.receiver
 *   hookReceiver();
 *   hookReceiver(BroadcastReceiverClass);
 *
 * 4. Hook an existing broadcast sender (via the Context.sendBroadcast() method):
 * Note that intents sent with LocalBroadcastManager will not be hooked.
 *
 *   frida -U --codeshare leolashkevych/android-broadcast-receiver -f com.application.sender
 *   hookSender();
 */


function registerReceiver(intentFilter) {
    Java.perform(function() {
        var cxt = getContext();
        if (cxt) {
            const parent = BroadcastReceiver().$new();
            cxt.registerReceiver(ChildBroadcastReceiver().$new(parent), Java.use('android.content.IntentFilter').$new(intentFilter));
        }
    });
}

function registerReceiverForAll() {
    Java.perform(function() {
        var Modifier = Java.use('java.lang.reflect.Modifier');
        var String = Java.use('java.lang.String');
        const parent = BroadcastReceiver().$new();
        var intent = Java.use('android.content.Intent').$new();
        var fields = intent.getClass().getDeclaredFields();
        for (var i = 0; i < fields.length; i++) {
            var field = fields[i];
            var modifiers = field.getModifiers();
            if (Modifier.isPublic(modifiers) && Modifier.isStatic(modifiers) && Modifier.isFinal(modifiers) && field.getType().equals(String.class)) {
                var filter = field.get(intent);
                if (filter) {
                    console.log('Global BroadcastReceiver -> Registered: ' + filter);
                    getContext().registerReceiver(ChildBroadcastReceiver().$new(parent), Java.use('android.content.IntentFilter').$new(filter));
                }
            }
        }
    });
}


function hookReceiver(receiverClassID) {
    if (typeof receiverClassID == 'undefined') {
        receiverClassID = 'android.content.BroadcastReceiver';
    }
    Java.perform(function() {
        var ReceiverClass = Java.use(receiverClassID);
        if (ReceiverClass) {
            ReceiverClass.onReceive.implementation = function(context, intent) {
                printIntent(intent);
                return this.onReceive(context, intent);
            };
            console.log("[+] BroadcastReceiver (" + receiverClassID + ") hook loaded.");
        }
    });
}

function hookSender() {
    Java.perform(function() {
        var Context = Java.use('android.content.Context');
        Context.sendBroadcast.overload('android.content.Intent').implementation = function(intent) {
            printIntent(intent);
            return this.sendBroadcast(intent);
        };
        console.log("[+] Context.sendBroadcast() hook loaded.");
    });
}

function getContext() {
    return Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
}

function BroadcastReceiver() {
    const ParentBroadcastReceiver = Java.registerClass({
        name: 'ParentBroadcastReceiver',
        superClass: Java.use('android.content.BroadcastReceiver'),
        fields: {
            parent: 'android.content.BroadcastReceiver'
        },
        methods: {
            onReceive: [{
                returnType: 'void',
                argumentTypes: ['android.content.Context', 'android.content.Intent'],
                implementation: function(context, intent) {
                    printIntent(intent);
                }
            }]
        },
    });
    return ParentBroadcastReceiver;
}

function ChildBroadcastReceiver() {
    const ChildBroadcastReceiver = Java.registerClass({
        name: 'ChildBroadcastReceiver',
        superClass: Java.use('android.content.BroadcastReceiver'),
        fields: {
            parent: 'android.content.BroadcastReceiver'
        },
        methods: {
            '<init>': [{
                returnType: 'void',
                argumentTypes: [],
                implementation: function() {}
            }, {
                returnType: 'void',
                argumentTypes: ['android.content.BroadcastReceiver'],
                implementation: function(parent) {
                    this.parent.value = parent;
                }
            }],
            onReceive: [{
                returnType: 'void',
                argumentTypes: ['android.content.Context', 'android.content.Intent'],
                implementation: function(context, intent) {
                    this.parent.value.onReceive(context, intent);
                }
            }]
        },
    });
    return ChildBroadcastReceiver;
}

function printIntent(intent) {
    console.log("\n[*] Intent received. Action: " + intent.getAction());
    var keys = intent.getExtras().keySet();
    var extras = "";
    var iterator = keys.iterator();
    for (var i = 0; i < keys.size(); i++) {
        if (iterator.hasNext()) {
            var key = iterator.next();
            extras += "\n" + key + " = " + intent.getExtras().get(key);
        }
    }
    console.log("[*] Extras:" + extras);
}