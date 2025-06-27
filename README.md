# AmneziaWG installer

**This project is a bash script that aims to setup a [AmneziaWG](https://docs.amnezia.org/ru/documentation/amnezia-wg/) VPN on a Linux server, as easily as possible!**

## Requirements

Supported distributions:

- AlmaLinux >= 9
- Debian >= 11
- Rocky Linux >= 9
- Ubuntu >= 24.04 - 25.04

others can work but not tested

2Gb of free space is required for temporary files.
![image](https://github.com/user-attachments/assets/0d58011d-82c8-410d-a8f2-a58d0a0aa638)


## Usage

Before installation it is strictly recommended to upgrade your system to the latest available version and perform the reboot afterwards.

Use curl or wget to download the script:
```bash
curl -O https://raw.githubusercontent.com/potap1978/amneziawg-install/main/amneziawg-install.sh
```
```bash
wget https://raw.githubusercontent.com/potap1978/amneziawg-install/main/amneziawg-install.sh
```

For Ubuntu 25.04
```bash
curl -O https://raw.githubusercontent.com/potap1978/amneziawg-install/main/amneziawg-install-Add_SRC_For-Ubuntu_25.04.sh
```
```bash
wget https://raw.githubusercontent.com/potap1978/amneziawg-install/main/amneziawg-install-Add_SRC_For-Ubuntu_25.04.sh
```

Set permissions:
```bash
chmod +x amneziawg-install.sh
```
And execute:
```bash
./amneziawg-install.sh
```

-= For Ubuntu 25.04 =-

Set permissions:
```bash
chmod +x amneziawg-install-Add_SRC_For-Ubuntu_25.04.sh
```
And execute:
```bash
./amneziawg-install-Add_SRC_For-Ubuntu_25.04.sh
```

Answer the questions asked by the script and it will take care of the rest.

It will install AmneziaWG (kernel module and tools) on the server, configure it, create a systemd service and a client configuration file.

Run the script again to add or remove clients!
