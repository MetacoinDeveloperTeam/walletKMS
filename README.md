# INBLOCK’s KeyManagementSystem(KMS)

INBLOCK’s KMS provides the wallet service to keep the Digital Asset, stores the Private Key and creates the signature using the stored Private Key.

The most important thing in a Digital Asset Trading is the signature how to authenticate the transaction requested by you.

When User A transfer the 100 MTC to User B,
A makes a signature using A’s private key to verify that this transaction requested by A and requests the transaction attached with this signature. Then it requests the transaction by attached this signature.

Metacoin checks whether the signature is correct by using the Public Key stored in the wallet created by User A.

It was the most import issue how to protect the Private Key in the digital asset wallet.

The 90% of the sensitive data leaking such as Private Key is caused by internal employees. It must be the critical treat whether this is a mistake or intentional.
There is the way to encrypt the internal data with Hardware Security Module(HSM).

But This Unencrypted data

![Without encryption](https://miro.medium.com/max/875/1*Bw7KNjIH3T8g3zhg0mLcSg.png)
or
![Encryption in Application](https://miro.medium.com/max/875/1*OPLjEL-TMMlEzCtx32NhjQ.png)
to
![Using HSM](https://miro.medium.com/max/875/0*JyOfHsPaps-E4Zco.png)

has to modify the previously developed application, and it depends on developers whether the data is securely encrypted or Key is well managed.

---

- There is a very simple program with 2 functions that allows the user to save and retrieve the data.
- It is created properly and reasonable included the user’s authentication process.
- It’s provided the data to the authenticated users. but it can be accessed by application developers or O/S operator without an authentication process.
- Even if the data is encrypted, the developers know the encryption method of the data and the storage location of the encryption key. This is same as the unencrypted one.

---

INBLOCK’s KMS runs on IBM Hyper Protect Virtual Servers (HPVS) in IBM LinuxONE.
![Inblock KMS](https://miro.medium.com/max/875/1*0_OQPvn-ruMJ4W5flKdMWQ.png)

All data is encrypted and stored by running user’s application in an isolated environment.(Developers are not involved in the encryption process.) it can not access the filesystem in anyway.

If you’re a developer, you can see the very simple source code of KMS.(https://github.com/MetacoinDeveloprTeam/walletKMS)

You can check that user’s data is saved in the “db” folder without any encryption.

There is a serious security fault if running on existing operating system.

But developers or operators can not be accessed the “db” folder with running on HPVS. It is not possible to arbitrarily change the running program.

INBLOCK is pleased to offer the Wallet service which solves the security threat in the past.

---

# This program is safe when running in the HPVS environment of LinuxONE as shown below, and additional encryption implementation is required in other environments.

- Adding the registry to HPVS
```shell
$ cat config/securebuild/kms_secure_create.yml
repository_registration:
   docker:
      repo: 'inblock/wallet_kms'
      pull_server: 'docker_pull'
      content_trust_json_file_path: '/root/.docker/trust/tuf/docker.io/inblock/wallet_kms/metadata/root.json'
   signing_key:
      private_key_path: '/root/hpvs/config/securebuild/keys/InblockKMS.private'
      public_key_path: '/root/hpvs/config/securebuild/keys/InblockKMS.pub'

$ hpvs regfile create --config config/securebuild/kms_secure_create.yml  --out config/encryptedKMS.enc
```


- Deploy to HPVS
```shell
$ cat walletKMS.yml
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

$ DOCKER_CONTENT_TRUST=0; docker build -t inblock/wallet_kms:1.0.2 .
$ DOCKER_CONTENT_TRUST=1; docker push inblock/wallet_kms:1.0.211
$ hpvs deploy --config config/walletKMS.yml
```
