# walletKMS
Inblock KMS(KeyManagementSystem)



cat config/securebuild/kms_secure_create.yml
repository_registration:
   docker:
      repo: 'inblock/wallet_kms'
      pull_server: 'docker_pull'
      content_trust_json_file_path: '/root/.docker/trust/tuf/docker.io/inblock/wallet_kms/metadata/root.json'
   signing_key:
      private_key_path: '/root/hpvs/config/securebuild/keys/InblockKMS.private'
      public_key_path: '/root/hpvs/config/securebuild/keys/InblockKMS.pub'

hpvs regfile create --config config/securebuild/kms_secure_create.yml  --out config/encryptedKMS.enc



cat walletKMS.yml
version: v1
type: virtualserver
virtualservers:
- name: walletKMS
  host: SSC4HPVS
  repoid: wallet_kms
  imagetag: 1.0.2
  reporegfile: /root/hpvs/config/encryptedKMS.enc
  resourcedefinition:
     ref: small
  networks:
   - ref:  external_network
     ipaddress: 192.168.20.121
  ports:
   - hostport: 10210
     protocol: tcp
     containerport: 10210
  volumes:
   - name: walletKMS
     ref : np-medium
     mounts:
      - mount_id: data
        mountpoint: /data
        filesystem: ext4
        size: 4GB


# build docker image
DOCKER_CONTENT_TRUST=0; docker build -t inblock/wallet_kms:1.0.2 .
DOCKER_CONTENT_TRUST=1; docker push inblock/wallet_kms:1.0.211
hpvs deploy --config config/walletKMS.yml
