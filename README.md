# εxodus core [![Build Status](https://travis-ci.org/Exodus-Privacy/exodus-core.svg?branch=v1)](https://travis-ci.org/Exodus-Privacy/exodus-core)
Contains:
* Static analysis 
* Network analysis
* Connection helper 

## Installation 
Clone this repository:
```
git clone https://github.com/Exodus-Privacy/exodus-core.git
cd exodus-core
```
Install `dexdump`:
```
sudo apt-get install dexdump
```
Create a `gplaycli` configuration file:
```
nano ~/.config/gplaycli/gplaycli.conf
```
containing
```
[Credentials]
gmail_address=
gmail_password=
#keyring_service=gplaycli
token=True
token_url=https://matlink.fr/token/email/gsfid

[Cache]
token=~/.cache/gplaycli/token

[Locale]
locale=en_US
timezone=CEST
```
Create Python `virtualenv`:
```
virtualenv venv -p python3
source venv/bin/activate
```
Install dependencies:
```
pip install -r requirements.txt
```
Run tests:
```
python -m unittest discover -s exodus_core -p "test_*.py"
```

## Include it to your project
Add the following line in your `requirements.txt`:
```
https://github.com/Exodus-Privacy/exodus-core/releases/download/v1.0.14/exodus_core-1.0.14.tar.gz
```
