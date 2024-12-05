# apache2_httpd_bearer_basic_hybrid_mod
Mod to make you can set BASIC auth when bearer token is not present or is not valid.

Example config
```
<Location />
                <If "%{HTTP:Authorization} =~ /^Bearer/">
                        AuthType validatebearertoken
                        AuthName "Token Authentication"
                        ValidateBearerTokenScript /usr/local/bin/validate_bearer_token.sh
                        Require valid-user
                </If>
                <Else>
                        AuthType Basic
                        AuthName "Restricted Content"
                        AuthUserFile /etc/apache2/sites-enabled/example.com/pwd-file
                        Require valid-user
                </Else>
</Location>
```
