import re
import os
import falcon
import requests
from wsgiref import simple_server
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
        logger.debug(f"cache_info: {cache_info}")
        if cache_info.hits > MAX_HITS:
            logger.info(f"Clearing the cache after {MAX_HITS} hits")
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
    headers = {"Authorization": f"Bearer {KUBERNETES_TOKEN}"}
    url = f"{KUBERNETES_URL}/api/v1/namespaces/logging/pods?labelSelector=component=fluentd"
    logger.debug(f"Requesting pods to kubernetes. url={url}, headers={headers}")
    r = requests.get(url, headers=headers, verify=False)
    if not r.ok:
        logger.warn(f"Error requesting pods from kubernetes: {r.body}")
        return falcon.HTTPInternalServerError(title="Error requesting pods from kubernetes")

    pods = r.json()
    logger.debug(f"Number of pods obtained: {len(pods)}")
    name = None

    logger.debug(f"Looking for a pod in node {node}")
    for pod in pods.get("items"):
        nodeName = pod.get("spec").get("nodeName")
        logger.debug(f"Comparing to {nodeName}")

        if re.match(f"(?i){node}.*", nodeName):
            name = pod.get("metadata").get("name")
            ip = pod.get("status").get("podIP")
            logger.debug(f"Match. Pod name: {name}, IP: {ip}")
            break
        else:
            continue

    if name:
        return falcon.HTTPFound(f"http://{ip}:24220/api/plugins.json")

    return falcon.HTTPNotFound(title="Not found fluentd pod for that node")

application = falcon.API()
application.add_route('/{node}', Redirect())
application.add_route('/clear', ClearCache())

if __name__ == '__main__':
    httpd = simple_server.make_server('127.0.0.1', 8000, application)
    httpd.serve_forever()
