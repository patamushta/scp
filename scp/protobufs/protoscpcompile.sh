for fname in `ls *.proto`; do 
    protoc $fname --python_out=.; 
done
