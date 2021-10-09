console.log("\n[+] Socket connection monitoring starts...")
console.log("---------------------------------------------\n")

var sock = Java.use("java.net.Socket");
		
// Socket.bind()
sock.bind.implementation = function(localAddress){
    console.log("Socket.bind("+localAddress.toString()+")");
    sock.bind.call(this, localAddress);
}

// Socket.connect(endPoint)
sock.connect.overload("java.net.SocketAddress").implementation = function(endPoint){
    console.log(">>> Socket Connection: "+endPoint.toString());
    sock.connect.overload("java.net.SocketAddress").call(this, endPoint);
}

// Socket.connect(endPoint, timeout)
sock.connect.overload("java.net.SocketAddress", "int").implementation = function(endPoint, tmout){
    console.log(">>> Socket Connection: "+endPoint.toString());
    sock.connect.overload("java.net.SocketAddress", "int").call(this, endPoint, tmout);
}

// Socket.getInetAddress()
sock.getInetAddress.implementation = function(){
    ret = sock.getInetAddress.call(this);
    console.log(ret.toString()+" Socket.getInetAddress()");
    return ret;
}

// new Socket(Proxy)
sock.$init.overload("java.net.Proxy").implementation = function(proxy){
    console.log("new Socket(Proxy: '"+proxy.toString()+"') called");
    this.$init.overload("java.net.Proxy").call(this, proxy);
}

// new Socket(host, port, localInetAddr, localPort)
sock.$init.overload("java.lang.String", "int", "java.net.InetAddress", "int").implementation = function(host,port, localInetAddress, localPort){
    console.log("new Socket(Host: '"+host+"', RemPort: "+port+", LocalInet: '"+localInetAddress+"', localPort: "+localPort+") called");
    this.$init.overload("java.lang.String", "int", "java.net.InetAddress", "int").call(this, si);
}