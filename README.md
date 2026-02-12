# tesk-vm-deploy

<!-- make sure to call out that if on windows they should use choco to install everything where possible -->
<!-- make sure to call out that if using 5s-tes egress minio they have to manually make the secret -->
<!-- 
apiVersion: v1
kind: Secret
metadata:
  name: aws-secret
stringData:
  config: |
    [default]
    endpoint_url=http://host:port
  credentials: |
    [default]
    aws_access_key_id=redact
    aws_secret_access_key=redact
 -->