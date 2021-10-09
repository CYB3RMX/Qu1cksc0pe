var base64 = Java.use('android.util.Base64');


base64.decode.overloads[0].implementation = function(endString, flags){
    
    console.log('>>> Base64 decode called:');
    console.log('-> INPUT: '+endString);    
    console.log('-> OUTPUT: '+byteArrayToString(this.decode(endString,flags)));
    return this.decode(endString,flags);
}

base64.encode.overloads[0].implementation = function(byteString, flags){
   

    console.log('>>> Base64 encode called:');
    console.log('-> INPUT: '+byteArrayToString(byteString));
    console.log('-> OUTPUT: '+byteArrayToString(this.encode(byteString,flags)));
    return this.encode(byteString,flags);
}

base64.encode.overloads[1].implementation = function(byteString, offset,ln,flags){
 

    console.log('>>> Base64 encode called:');
    console.log('-> INPUT: '+byteArrayToString(byteString));
    console.log('-> OUTPUT: '+byteArrayToString(this.encode(byteString,offset,ln,flags)));
    return this.encode(byteString,offset,ln,flags);
}

base64.encodeToString.overloads[1].implementation = function(byteString,flags){

    console.log('>>> Base64 encodeToString called:');
    console.log('-> INPUT: '+byteArrayToString(byteString));
    console.log('-> OUTPUT: '+this.encodeToString(byteString,flags));
    return this.encodeToString(byteString,flags);
}
