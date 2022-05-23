# oioioi-submit
Tool that you can use to subit codes to oioioi (https://github.com/sio2project/oioioi) - based websites via backend

Requierments:
1. Python 3.5.5 or greater
2. python library `requests`
3. python library `requests-toolbelt`
4. python library `bs4`

Instalation:
1. Install the required libraries : `pip install requests requests-toolbelts bs4`
2. Download the appropiate submit.py file

Basic ussage:
1. Configure the tool using `./submit.py -i`. This command will ask you for basic info : oioioi adress, username and password. The info will be saved in `.oioioi-submit-config` in your home directory. If you wish not to store your credentials in a file, leve them empty and you will be prompted during submission.
2. Submit a solution using `./submit.py -t <problem_code> [file to submit]`

Problem codes are displayed in the first column in problem list. You can also acces them by writing an invalid one - the script will print a list of problems and their codes.
