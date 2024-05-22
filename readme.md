Allows to control resources for specific container if not possible to set as usual. Enforces tagging policy for all images

## Admission controller functionality:
- Custom labels to the deployments and pods on CREATE and UPDATE actions.
- Resources section for each predefined container with configured requests and limits if not set.
- Restrict deployment of images with "latest" tag

`In this example CertManager CA is used as SSL certificate for Flask application.`

