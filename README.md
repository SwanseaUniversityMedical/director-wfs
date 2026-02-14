# Director WFS

This has been tested on:
- OSX (arm64), GUI
- Ubuntu 24 (arm64 and x86), GUI
- Debian 12 (arm64 and x86), headless

## OSX/Apple users
If you're running this on an arm64 Apple machine, make sure your Docker Desktop settings have "use containerd for pulling and storing images" selected.

## Running the script

You can one-shot run the script with 

`bash <(curl -s https://raw.githubusercontent.com/SwanseaUniversityMedical/director-wfs/feat/extra-install/director-wfs.sh)`

which will show you the required and optional script args.

For an easy test/play example that isn't linked to a real S3, meaning TESK jobs will fail, but still gives you a fully functioning cluster with everything installed/deployed, you can use the command 

`bash <(curl -s https://raw.githubusercontent.com/SwanseaUniversityMedical/director-wfs/feat/extra-install/director-wfs.sh) localtest.me admin1 https://rustfs.localtest.me rustfsadmin rustfsadmin`

This will set all ingresses to be sub-addresses of `localtest.me` (which resolves to localhost so you can access argo etc from the machine you're running the script on), and the argocd and grafana admin user passwords will both be set to `admin1`.
The s3 config args are only used to pass through the configuration to TESK so it doesn't matter that they don't point at anything and that we don't actually have a S3 service running at `https://rustfs.localtest.me`.
As we don't pass any certificate files the script will generate its own self-signed Root CA and Intermediate signing cert.


## Product Website

Product Description (https://ukserp.notion.site/director-workflow-server-d-wfs)
