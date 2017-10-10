import re
import os
import falcon
import requests
from functools import lru_cache

import logging
logging.basicConfig()
logger = logging.getLogger(__name__)

# Remove warning about SSL
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ENV vars
MAX_HITS = os.getenv("MAX_HITS", 4)
KUBERNETES_URL = os.getenv("KUBERNETES_URL", "https://kubernetes.default.svc.cluster.local")
KUBERNETES_TOKEN = os.getenv("KUBERNETES_TOKEN")
LOG_LEVEL = os.getenv("LOG_LEVEL", logging.INFO)

# Define log level (DEBUG=10, INFO=20, WARNING=30)
logger.setLevel(int(LOG_LEVEL))

class ClearCache(object):
    """
    Clear the LRU cache. Force to ask to kubernetes next time
    """
    def on_get(self, req, resp):
        logger.info("Clearing the cache requested")
        resp.status = falcon.HTTP_200
        get_redirect.cache_clear()

class Redirect(object):
    def on_get(self, req, resp, node):
        if not node:
            raise falcon.HTTPBadRequest(title="Missing parameter")

        ex = get_redirect(node)
        cache_info = get_redirect.cache_info()
        logger.debug("cache_info: %s" % str(cache_info))
        if cache_info.hits > MAX_HITS:
            logger.info("Clearing the cache after %s hits" % MAX_HITS)
            get_redirect.cache_clear()

        raise ex

@lru_cache(maxsize=16)
def get_redirect(node):
    """
    Obtain all pods from namespace logging.
    Find the pod running in the node provided by parameter
    Return a redirect to that pod, to the monitoring url

    Returning Exceptions instead of raising to be able to use lru_cache
    """
    headers = {"Authorization": "Bearer %s" % KUBERNETES_TOKEN}
    url = "%s/api/v1/namespaces/logging/pods?labelSelector=component=fluentd" % KUBERNETES_URL
    logger.debug("Requesting pods to kubernetes. url=%s, headers=%s" % (url, headers))
    r = requests.get(url, headers=headers, verify=False)
    if not r.ok:
        logger.warn("Error requesting pods from kubernetes: %s" % r.body)
        return falcon.HTTPInternalServerError(title="Error requesting pods from kubernetes")

    pods = r.json()
    logger.debug("Number of pods obtained: %s" % len(pods.get("items")))
    name = None

    logger.debug("Looking for a pod in node %s" % node)
    for pod in pods.get("items"):
        nodeName = pod.get("spec").get("nodeName")
        logger.debug("Comparing to %s" % nodeName)

        if re.match("(?i)%s.*" % node, nodeName):
            name = pod.get("metadata").get("name")
            ip = pod.get("status").get("podIP")
            logger.debug("Match. Pod name: %s, IP: %s" % (name,ip))
            break
        else:
            continue

    if name:
        return falcon.HTTPFound("http://%s:24220/api/plugins.json" % ip)

    return falcon.HTTPNotFound(title="Not found fluentd pod for that node")

application = falcon.API()
application.add_route('/{node}', Redirect())
application.add_route('/clear', ClearCache())
