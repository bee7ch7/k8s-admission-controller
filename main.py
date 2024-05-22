import logging
from flask import Flask, request, jsonify
import base64
import jsonpatch
import json
import copy

admission_controller = Flask(__name__)

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
# predefined resources section if not set
resource_patch_operations = {
       "op": "add", "path": "/spec/template/spec/containers/0/resources", "value": {
        "requests": {
            "cpu": "100m",
            "memory": "200Mi"
        },
        "limits": {
            "cpu": "200m",
            "memory": "400Mi"
        }
    }}

# add custom labels
all_patches = [
   {"op": "add", "path": "/metadata/labels/custom_label", "value": "custom_value"},
   {"op": "add", "path": "/spec/template/metadata/labels/custom_label", "value": "custom_value"},
  ]

@admission_controller.before_request
def log_request_info():
    json_request = json.loads(request.get_data())
    pretty_json = json.dumps(json_request, indent=4)
    uid = json.loads(request.get_data()).get('request', {}).get('uid', None)

    logging.info(f"Request: {request.method} {request.url} from {request.remote_addr}")
    logging.info(f"Headers: {request.headers}")
    logging.info(f"Body: {pretty_json}")
    logging.info(f"request_id: {uid}")

@admission_controller.route('/mutate/deployments', methods=['POST'])
def deployment_webhook_mutate():
    request_info = request.get_json()
    json_request = json.loads(request.get_data())
    uid = json.loads(request.get_data()).get('request', {}).get('uid', None)
   
    # check if latest tag is used and drop request if so
    for idx, container in enumerate(json_request["request"]["object"]['spec']['template']['spec']['containers']):
      if ":latest" in container['image'] or ":" not in container['image']:
        response = {
          "apiVersion": "admission.k8s.io/v1",
          "kind": "AdmissionReview",
          "response": {
              "uid": uid,
              "allowed": False,
              "status": {"message": f"Image tag 'latest' is not allowed. Check container with image '{container['image']}'"}
          }
         }

        return jsonify(response)
      
    for idx, container in enumerate(json_request["request"]["object"]['spec']['template']['spec']['containers']):
      if "nginx" in container['image'] and not container['resources']:
        patched_operation = copy.deepcopy(resource_patch_operations)
        patched_operation["path"] = patched_operation["path"].replace("/0/", f"/{idx}/")
        all_patches.append(patched_operation)

      if "busybox" in container['image'] and not container['resources']:
        patched_operation = copy.deepcopy(resource_patch_operations)
        patched_operation["path"] = patched_operation["path"].replace("/0/", f"/{idx}/")

        patched_operation["value"]["requests"]["cpu"] = "150m"
        patched_operation["value"]["limits"]["cpu"] = "300m"
        patched_operation["value"]["requests"]["memory"] = "200Mi"
        patched_operation["value"]["limits"]["memory"] = "300Mi"

        all_patches.append(patched_operation)
       
    return admission_response_patch(True, uid, "Adding allow label", json_patch = jsonpatch.JsonPatch(all_patches))

def admission_response_patch(allowed, uid, message, json_patch):
    base64_patch = base64.b64encode(json_patch.to_string().encode("utf-8")).decode("utf-8")
    admission_response = {
        "uid": uid,
        "allowed": allowed,
        "status": {"message": message},
        "patchType": "JSONPatch",
        "patch": base64_patch}

    logging.info(f"Json patch: {json_patch}")
    logging.info(f"response: {admission_response}")

    response = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": admission_response
    }

    return jsonify(response)

if __name__ == '__main__':
    admission_controller.run(host='0.0.0.0', port=443, ssl_context=("/app/certs/tls.crt", "/app/certs/tls.key"))