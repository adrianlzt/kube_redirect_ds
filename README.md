# kube_redirect_ds
Redirect queries to a particular pod of a Daemon Set based on the node name.

This small app tries to solve the problem when we need to query a certain pod of a Daemon Set but we only know the node where it is running.

Making a request to this app it will return a HTTP Redirect to the internal POD IP.
