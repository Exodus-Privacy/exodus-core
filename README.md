# εxodus core
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

## Include it in your project
Add the following line in your `requirements.txt`:
```
git+https://github.com/Exodus-Privacy/exodus-core.git   
```
