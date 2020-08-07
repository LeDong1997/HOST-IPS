# HOST-IPS
Building Host based IPS for Linux and Windows
#
# Windows

## Setup environment
This project using `Python 3.8.1` on Windows 10 64 bit

About IDE and Editor: Pycharm, Visual Studio Code, Sublime Text 3

### Create Virtual Environment
`> pip install virtualenv`

`> cd Host-IPS`

`> virtualenv venv`

Run project in virtual environment

`> .\venv\Scripts\activate`

`> python demo.py`

Exit project in virtual environment

`> .\venv\Scripts\deactivate.bat`

### On Visual Studio Code

The message `Error: Cannot be loaded because running scripts is disabled on this system.`

To fix the error, run the command below

`> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process`

Back to step create virtual environment

## Install library for project
Run project in virtual environment

`> pip install -r requirements_windows.txt`

## Note
Setup Windows Audit Log
* https://gallery.technet.microsoft.com/scriptcenter/How-to-audit-changed-39afba72#content
* Run program with Administrator permission

#
# Linux

## Setup environment
This project using `Python 3.6` on Ubuntu 18.04-LTS 64 bit

About IDE and Editor: Pycharm, Visual Studio Code, Sublime Text 3

### Create Virtual Environment
`$ pip install virtualenv`

`$ cd Host-IPS`

`$ virtualenv venv`

Run project in virtual environment

`$ source /venv/bin/activate`

`$ python demo.py`

Exit project in virtual environment

`$ deactivate`

## Install library for project
Run project in virtual environment

`$ pip install -r requirements_linux.txt`

Install audit library in Linux

`$ sudo apt-get install auditd -y`

Start and enable audit service in the system

`$ sudo systemctl start auditd & sudo systemctl enable auditd`

## Database alert for object monitor
There are 6 columns in table

Time    User    Syscall     Resource    Process     State

"2020-08-07 08:08:29" "bkcs"    "openat"    "/home/bkcs/Desktop/teptin" "/bin/nano" "yes" 
