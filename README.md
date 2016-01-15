XJWT
====

XJWT is a [JSON Web Token](https://jwt.io/introduction/) authenticator for 
HTTP applications that use [XHandler](https://github.com/rs/xhandler).

It lets you verify the JWT signature and the payload issuer and audience
claims.  You may also enable Basic Auth, enabling the request access if
specified credentials are included.

Installing
----------
```
go get github.com/dailymotion/xjwt
```

Usage
-----
```go
c := xjwt.Config{
    Secret: "5d63GMY5fRsBRdB7cDsMoLlNX9vWxNSq",
    Issuer: "dmissuer",
    Audiences: []string{"dm"},
    BasicUser: "dmxadmin",
    BasicPass: "xhunterx",
    Skip: []string{"/healthz"},
}

c := xhandler.Chain{}
c.UseC(xjwt.NewHandler(c))
```

See [XHandler](https://github.com/rs/xhandler) for how to use Xhandler.

Licenses
--------
All source code is licensed under the 
[MIT License](https://raw.githubusercontent.com/dailymotion/xjwt/master/LICENSE).
