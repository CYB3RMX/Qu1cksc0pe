rpc.exports = {
    readBytes: function(address, size){
        return Memory.readByteArray(ptr(address), size);
    },
    enumerateRanges: function(prot){
        return Process.enumerateRangesSync({protection: prot, coalesce: true});
    },
    hookLinuxSyscall: function(target_api, target_arg){
        Interceptor.attach(ptr(Module.getExportByName(null, target_api)), {
            onEnter(args){
                send({
                    target_api: target_api,
                    args: args[target_arg].readUtf8String()
                });
            }
        });
        setTimeout(2000);
    }
}