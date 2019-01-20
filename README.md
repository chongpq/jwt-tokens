Prerequisites
  * Docker 17.05 or higher - I've run this on Docker version 18.09.1, build 4c52b90

Running 
  * docker build -t paul/jwt .
  * On a POSTIX box run docker run --rm -e TOKEN_SECRET='secret' -p 8000:8000 paul/jwt > jwt.log & (Windows boxes are quite similar)

You can obviousely change your TOKEN_SERCRET, the port sxposed on the host or log name/location to suit your needs.

```docker run --rm -e TOKEN_SECRET=<TOKEN_SECRET> -p <host port>:8000 paul/jwt > <log name/location> &```

Notes

This project implements a oauth 2.0 like authorization. The /login and /refresh endpoints being the authorization server and the / the resource server. I'm using the claims audience field to store the email address of the user.

The /login endpoint requires a POST and the username and password passed as form parameters.

```curl -X POST -d 'username=chongpq@gmail.com&password=yay!' http://<hostname:port>/login```

The /refresh endpoint requires a POST with the refresh token passed in the header.

```curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJjaG9uZ3BxQGdtYWlsLmNvbSIsImV4cCI6MTU0Nzk4MzQ4OH0.mdn6AwqMQuvdB1haXLM_LeaWikAeNZMGyzV1MnRlESg' -X POST http://<hostname:port>/refresh```

The / endpoint requires a GET and the access token passed in the header.

```curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJjaG9uZ3BxQGdtYWlsLmNvbSIsImV4cCI6MTU0Nzk4MzQ4OH0.mdn6AwqMQuvdB1haXLM_LeaWikAeNZMGyzV1MnRlESg' http://<hostname:port/```

Please note this implementation isn't production ready as the endpoint need to be protected by TLS. This can be provided by NginX implementing a sidecar patttern.

The next focus of dev would be tests, since I'm more or less finished dividing up the project into 3 repo's go style.
