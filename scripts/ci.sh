set -x
set -e
if [ -z $tagname ]; then echo "tagname not set"; exit 1; fi
docker build -t lijianying10/web3gateway:$tagname .
docker push lijianying10/web3gateway:$tagname

