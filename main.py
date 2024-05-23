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
      "op": "add", 
      "path": "/spec/containers/0/resources", 
      "value": {
        "requests": {
            "cpu": "100m",
            "memory": "200Mi"
        },
        "limits": {
            "cpu": "200m",
            "memory": "400Mi"
        }
      }
  }

enabled_image_checker = None
enabled_deployments = None
enabled_pods = None
enabled_labels = None
enabled_annotations = None
all_patches = []

try:
    with open('config/settings.json') as f:
        settings = json.load(f)
        enabled_image_checker = settings["checks"]["image_tags"]
        enabled_deployments = settings["checks"]["deployments"]
        enabled_pods = settings["checks"]["pods"]
        enabled_labels = settings["checks"]["labels"]
        enabled_annotations = settings["checks"]["annotations"]
except FileNotFoundError:
    print("Error: The file 'settings.json' was not found.")
    settings = None
except json.JSONDecodeError:
    print("Error: The file 'settings.json' contains invalid JSON.")
    settings = None
except Exception as e:
    print(f"An unexpected error occurred: {e}")
    settings = None



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
    json_request = json.loads(request.get_data())
    uid = json.loads(request.get_data()).get('request', {}).get('uid', None)
    resource_type = json.loads(request.get_data()).get('request', {}).get('requestResource', {}).get('resource', None)
   
    # check if latest tag is used and drop request if so
    if enabled_image_checker:    
      check_image_tags = admission_image_tag(uid, json_request["request"]["object"]['spec']['template']['spec']['containers'])
      if check_image_tags:
        return check_image_tags
      
    if enabled_deployments:
       configure_resources(json_request, settings, resource_type)
      
    if enabled_labels:
       add_labels_and_annotations(settings, resource_type, "labels")
      
    if enabled_annotations:
       add_labels_and_annotations(settings, resource_type, "annotations")
           
    return admission_response_patch(True, uid, "Adding allow label", json_patch = jsonpatch.JsonPatch(all_patches))

@admission_controller.route('/mutate/pods', methods=['POST'])
def pod_webhook_mutate():
    json_request = json.loads(request.get_data())
    uid = json.loads(request.get_data()).get('request', {}).get('uid', None)
    resource_type = json.loads(request.get_data()).get('request', {}).get('requestResource', {}).get('resource', None)

    # check if latest tag is used and drop request if so
    if enabled_image_checker:    
      check_image_tags = admission_image_tag(uid, json_request["request"]["object"]['spec']['containers'])
      if check_image_tags:
        return check_image_tags
    
    if enabled_pods:
       configure_resources(json_request, settings, resource_type)

    if enabled_labels:
       add_labels_and_annotations(settings, resource_type, "labels")
      
    if enabled_annotations:
       add_labels_and_annotations(settings, resource_type, "annotations")
      
    return admission_response_patch(True, uid, "Adding allow label", json_patch = jsonpatch.JsonPatch(all_patches))

def admission_response_patch(allowed, uid, message, json_patch):
    base64_patch = base64.b64encode(json_patch.to_string().encode("utf-8")).decode("utf-8")
    admission_response = {
        "uid": uid,
        "allowed": allowed,
        "status": {"message": message},
        "patchType": "JSONPatch",
        "patch": base64_patch
      }

    logging.info(f"Json patch: {json_patch}")
    logging.info(f"response: {admission_response}")

    response = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": admission_response
    }

    return jsonify(response)

def admission_image_tag(uid, containers):
  for idx, container in enumerate(containers):
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
  return False

def add_labels_and_annotations(settings, resource_type, type):
    # add global labels
    global_labels_and_annotations = settings.get(f'add_global_{type}', {})
    pod_config = settings.get(f'{resource_type}', {}).get('names', {})

    for k, v in global_labels_and_annotations.items():
        all_patches.append({"op": "add", "path": f"/metadata/{type}/{k}", "value": v})

        if resource_type in ["deployments", "statefulsets", "daemonsets"]:
            all_patches.append({"op": "add", "path": f"/spec/template/metadata/{type}/{k}", "value": v})

    for pod_name, pod_info in pod_config.items():
        labels_and_annotations = pod_info.get(f'add_{type}', {})
        for k, v in labels_and_annotations.items():
            all_patches.append({"op": "add", "path": f"/metadata/{type}/{k}", "value": v})

            if resource_type in ["deployments", "statefulsets", "daemonsets"]:
                all_patches.append({"op": "add", "path": f"/spec/template/metadata/{type}/{k}", "value": v})
   

def configure_resources(json_request, settings, resource_type):
    request_object = json_request.get('request', {}).get('object', {})
    resource_name = json_request.get('request', {}).get('object', {}).get('metadata', {}).get('name', None)

    logging.info(f"Resource name: {resource_name}")

    if 'spec' not in request_object:
        request_object['spec'] = {}

    names_config = settings.get(f'{resource_type}', {}).get('names', {})
    spec = request_object['spec']

    if 'containers' not in spec:
        spec['containers'] = []

    # Iterate over pod names in settings
    for pod_name, pod_info in names_config.items():
        if pod_name in resource_name:
          logging.info(f"Preparing patch for '{pod_name}' because it matches '{resource_name}'")

          container_names_config = pod_info.get('container_names', {})
          for container_name, container_info in container_names_config.items():
              resources_config = container_info.get('resources', {})

              # Find the container in the json_request spec containers
              for idx, container in enumerate(spec['containers']):
                  if container.get('name') == container_name and not any(f"/{idx}/" in operation["path"] for operation in all_patches):
                      patched_operation = copy.deepcopy(resource_patch_operations)

                      if resource_type != "pods":
                        patched_operation["path"] = patched_operation["path"].replace("/spec/containers/0/", f"/spec/template/spec/containers/{idx}/")
                      else:
                        patched_operation["path"] = patched_operation["path"].replace("/0/", f"/{idx}/")
                        
                      patched_operation["value"] = resources_config

                      all_patches.append(patched_operation)
                      break


if __name__ == '__main__':
    admission_controller.run(host='0.0.0.0', port=443, ssl_context=("/app/certs/tls.crt", "/app/certs/tls.key"))