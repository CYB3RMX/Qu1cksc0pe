rpc.exports = {
    readBytes: function(address, size){
        return Memory.readByteArray(ptr(address), size);
    },
    enumerateRanges: function(prot){
        return Process.enumerateRangesSync({protection: prot, coalesce: true});
    },
    hookWindowsApi: function(target_api){
        Interceptor.attach(ptr(Module.getExportByName(null, target_api)), {
            onEnter(args){
                if (target_api == "connect" || target_api == "sendto" || target_api == "WSAConnect"){
                    send({
                        target_api: target_api,
                        args: [args[1].readCString(), args[2].toInt()]
                    });
                } else {
                    send({
                        target_api: target_api,
                        args: Memory.readUtf16String(args[0])
                    });
                }
            }
        });
        setTimeout(2000);
    }
}