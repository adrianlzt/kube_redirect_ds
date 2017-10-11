# kube_redirect_ds
Redirect queries to a particular pod of a Daemon Set based on the node name.

This small app tries to solve the problem when we need to query a certain pod of a Daemon Set but we only know the node where it is running.

Making a request to this app it will return a HTTP Redirect to the internal POD IP.

Docker image: https://hub.docker.com/r/adrianlzt/kube_redirect_ds/

## Deploy
Template ``openshift.yaml`` is provided yo deploy this app in a OpenShift cluster.

Example of execution tu monitor fluent agent pods:
```
oc process -f openshift.yaml NAME="fluentd-monitoring" NAMESPACE="logging" LABEL_SELECTOR="component=fluentd" REDIRECT="http://{}:24220/api/plugins.json" AUTH_TOKEN="XXX" | oc create -f -
```

## Using
Once deployed, we can test if it is working (app and this test should be in the same project of fluent agents):

```
oc run test --rm=true -it --image=centos -- curl -L -D - $(oc get svc/fluentd-monitoring -o jsonpath="{.spec.clusterIP}")/$(oc get nodes -o jsonpath="{.items[0].metadata.name}")
```

This pod will run the command:
```
curl -L -D - 172.30.246.218/name-of-one-openshift-node
```

The app will resolve which pod with label ``component=fluentd`` is running on the node ``name-of-one-openshift-node`` and redirect the query:
```
HTTP/1.1 302 Found
Server: gunicorn/19.7.1
Date: Wed, 11 Oct 2017 12:15:40 GMT
Connection: close
location: http://172.21.23.206:24220/api/plugins.json
content-length: 0
content-type: application/json; charset=UTF-8
```

With the parameter ``-L``, ``curl`` will follow the redirect and show the response of the fluent agent monitoring api:

```
HTTP/1.1 200 OK
Content-Type: application/json
Server: WEBrick/1.3.1 (Ruby/2.0.0/2015-12-16)
Date: Wed, 11 Oct 2017 12:15:35 GMT
Content-Length: 6761
Connection: Keep-Alive

{"plugins":[{"plugin_id":"object:10ca7a0","plugin_category":"input...
```
