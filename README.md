Prerequites
	* Docker 17.05 or higher - I've run this on Docker version 18.09.1, build 4c52b90

Running 
  * docker build -t paul/jwt .
  * docker run --rm -e TOKEN_SECRET='secret' -p 8000:8000 paul/jwt > jwt.log &
