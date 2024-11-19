# script to get private and public key from project and generate signature
testString=testString
echo -n testString > data.txt
cp ../../../../projects/*/private_key.pem .
cp ../../../../projects/*/include/licensecc/*/public_key.h .
openssl dgst -sha512 -sign private_key.pem data.txt |base64 > signature.base64
echo "#define SIGNATURE \\" > signature.h
sed -e 's/^/	\"/' -e 's/$/\"	\\/' signature.base64 >> signature.h
echo >> signature.h
echo -n "#define SIGNATURE_LEN " >> signature.h
length=$(( $(du -b signature.base64|cut -f1)-$(wc -l signature.base64|cut -d' ' -f1) ))
echo $length >> signature.h
echo "#define TEST_STRING \"$testString\"" >> signature.h
