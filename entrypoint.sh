#!/bin/bash -xe

AWS_REGION="us-west-2" chamber exec oauth2-proxy -- \
    consul-template -once \
    -template "/oauth2_proxy.cfg.tmpl:/oauth2_proxy.cfg"
exec /oauth2-proxy -config=/oauth2_proxy.cfg -okta-domain="$OKTA_DOMAIN"
