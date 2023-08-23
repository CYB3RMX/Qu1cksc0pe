// This script is for enumerating common things about the target android application
rpc.exports = {
    // Hook socket connections
    hookSocketConnect: function () {
        var Socket = Java.use("java.net.Socket");
        Socket.connect.overload('java.net.SocketAddress').implementation = function (endpoint) {
            console.log(">>> Socket.connect called with endpoint: " + endpoint.toString());
            return this.connect.apply(this, arguments);
        };
    },
    // Hook java.net.InetAddress
    hookInetAddressGetAllByName: function () {
        var InetAddress = Java.use("java.net.InetAddress");
        InetAddress.getAllByName.overload('java.lang.String').implementation = function (host) {
            console.log(">>> InetAddress.getAllByName called with host: " + host);
            return this.getAllByName.apply(this, arguments);
        };
    },
    // Read bytes from address
    readBytes: function(address, size){
        return Memory.readByteArray(ptr(address), size);
    },
    // Enumerate memory ranges
    enumerateRanges: function(prot){
        return Process.enumerateRangesSync({protection: prot, coalesce: true});
    }
}