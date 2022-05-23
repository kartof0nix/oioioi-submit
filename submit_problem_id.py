#!/bin/python3
from getpass import getpass
import json
import sys
import requests
from argparse import ArgumentParser, ArgumentTypeError
from requests_toolbelt import MultipartEncoder
import webbrowser
from os.path import expanduser
from bs4 import BeautifulSoup
import time

DUMP_RESPONSE = False

requests.packages.urllib3.disable_warnings() 


SIO_headers = {
    "Upgrade-Insecure-Requests" : "1",
}


problem_ids ={

}


class PasswordAuth(requests.auth.AuthBase):
    def __init__(self, username, password, csrftoken) -> None:
        self.username = username
        self.password = password
        self.csrftoken = csrftoken
        super().__init__()
    def __call__(self, r):
        # Implement my authentication
        login_data = dict(username=self.username, password=self.password, csrfmiddlewaretoken=self.csrftoken)
        r.prepare_body(login_data, None)
        return r




global session, auth
session = requests.Session()
auth = requests.auth.AuthBase()

configuration = {}
config_path = expanduser('~/.oioioi-submit-config')

def main():
    parser = ArgumentParser(usage="./submit.py [-ih|-tkusw][-up|-T] [filename] (use ./submit.py -h for help)", description="Tool used for submitting solutions for SIO2.")

    save_config_and_configure_group = parser.add_mutually_exclusive_group()
    save_config_and_configure_group.add_argument('-i', '--configure',
                                                 action='store_true',
                                                 help="start interactive "
                                                      "configuration")
    save_config_and_configure_group.add_argument('-s', '--save-config',
                                                 action='store_true',
                                                 help="used along with --token "
                                                      "or/and --url, saves " +
                                                      "configuration changes "
                                                      "to configuration file")

    authentication_type = parser.add_mutually_exclusive_group()
    username_password = authentication_type.add_argument_group()
    username_password.add_argument('-u', '--username', action='store',
                        help="specify username for authentication")
    username_password.add_argument('-p', '--password', action='store',
                        help="specify password for authentication")  

    authentication_type.add_argument('-T', '--token', action='store',
                        help="provide token for authentication")                



    parser.add_argument('-t', '--task', action='store',
                        help="Task short name" +
                        "filename with extension is taken)")
    parser.add_argument('-U', '--url', action='store',
                        help="provide connection URL " +
                        "(e.g. http://oioioi.com)")
    parser.add_argument('-c', '--contest', action='store',
                        help="provide contest name " +
                        "(e.g. example-contest)")
    parser.add_argument('-w', '--webbrowser', action='store_true',
                        help="open the web browser after successful submission")
    parser.add_argument("filename", nargs='?')

    init_config()
    args = parser.parse_args()
    if args.url:
        configuration['oioioi-url'] = args.url
        if( not ( configuration['oioioi-url'].endswith('/'))):
            configuration['oioioi-url'] += '/'
    if args.contest:
        configuration['contest-name'] = args.contest
    if args.token:
        configuration['token'] = args.token
        configuration['auth-type'] = 't'
    if args.username and args.password:
        configuration['username'] = args.username
        configuration['password'] = args.password
        configuration['auth-type'] = 'p'
    if args.save_config:
        save_configuration()
    elif args.configure:
        return create_configuration()
    elif args.filename and args.task:        

        if(configuration['auth-type'] == 't'):
            authenticate(configuration['oioioi-url'],
                      configuration['contest-name'],
                      token=configuration['token'])
            
        elif(configuration['auth-type'] == 'p'):
            authenticate(configuration['oioioi-url'],
                      configuration['contest-name'],
                      username=configuration['username'],
                      password=configuration['password'])

        get_problem_dict(configuration['oioioi-url'], configuration['contest-name'])
        submit(args.filename, args.task,
                 configuration['oioioi-url'],
                 configuration['contest-name'],
                 args.webbrowser, 
                 token=(configuration['token'] if configuration['auth-type'] == 't' else None))
        
        #problem_id = get_id(args.task, configuration['oioioi-url'], configuration['contest-name'])
        return
                
    parser.print_usage()
    return 1

def init_config():
    # pylint: disable=global-statement
    global configuration
    try:
        json_data = open(config_path).read()
        configuration = json.loads(json_data)
    except IOError:
        configuration = {}

def create_configuration():
    print("Fill in the fields to create your configuration.", file=sys.stderr)
    while query('oioioi-url',
                "oioioi website (e.g. http://oioioi.com)"):
        pass
    if( not ( configuration['oioioi-url'].endswith('/'))):
        configuration['oioioi-url'] += '/'
    while query('contest-name',
                "contest name (e.g. example-contest)"):
        pass
    while query('auth-type', 
                "authentication type ('p' for password or 't' for token)"):
        pass
    if(configuration['auth-type'] == 't'):
        while query('token', "authentication token ( e.g. Basic QwEr1TyUiOp23", False):
            pass
    elif(configuration['auth-type'] == 'p'):
        while query('username', "username (e.g. sio-user ) ", False):
            pass
        while query('password', "password (e.g. 12345678 ) ", True):
            pass
    return save_configuration()


def save_configuration():
    try:
        with open(config_path, 'w') as config_file:
            config_file.write(json.dumps(configuration))
        print("Configuration has been saved successfully.", file=sys.stderr)
        return 0
    except Exception as e:
        print("Could not write configuration: %s" % e, file=sys.stderr)
        print(e.with_traceback())
        return 1

def query(key, value_friendly_name, mask_old_value=False):
    print("Enter new value for %s or press Enter." % value_friendly_name,
            file=sys.stderr)
    old_value = configuration.get(key)
    if not old_value:
        old_value = ''
    if not mask_old_value:
        new_value = input('[%s] ' % (key if mask_old_value and key
                                         in configuration else old_value))
    else:
        new_value = getpass()
                            
    if new_value:
        configuration[key] = new_value
    elif not new_value and key not in configuration:
        print("You must provide a value.", file=sys.stderr)
        return True
    return False
    

def authenticate(server_url, contest_name, token=None, username=None, password=None):
    
    try:
        csrftoken = None
        #task_url = None
        if(token):
            auth = requests.auth.HTTPTokenAuth(token)
            #task_url = server_url + 'api/c/' + contest_name + '/submit/' 
        if(username and password):
            #task_url = server_url + 'c/' + contest_name + '/submit/' 
            login_url = server_url + 'c/' + contest_name + '/login/'
            #Ger crsft token
            global r
            r = session.get(login_url, headers=SIO_headers)
            if(DUMP_RESPONSE):
                snap = open('dump_auth.html', 'w')
                snap.write(r.text)
                snap.close()
            csrftoken = session.cookies['csrftoken']
            # Authenticate!
            global r2
            r2 = None
            while(r2 == None or r2.url != configuration['oioioi-url']):
                print("Authenticating...")
                auth = PasswordAuth(username, password, csrftoken)
                r2 = session.post(login_url, auth = auth, headers=SIO_headers, verify=False)
                snap = open('dump2.html', 'w')
                snap.write(r2.text)
                snap.close()

                csrftoken = session.cookies['csrftoken']
                if(r2.url == configuration['oioioi-url']):
                    continue
                print("\033[31;1mInvalid username and/or password!\033[0m Please try again:")
                while query('username', "username (e.g. sio-user ) ", False):
                    pass
                while query('password', "password (e.g. 12345678 ) ", True):
                    pass
                username = configuration['username']
                password = configuration['password']

        else:
            raise ArgumentTypeError('You must provide either token or username and passowrd')
    except Exception as e:
        print("Error:", e, file=sys.stderr)
        #print(e.with_traceback())
        print("\033[31;1mSubmission failed.\033[0m", file=sys.stderr)
        return 1
def submit(filename, task_name, server_url, contest_name, open_webbrowser, token=None):
    #print(filename, task_name, token, server_url, contest_name, open_webbrowser)
    if( not task_name in problem_ids ):
        print("\033[31mNot a vaild problem code!\033[0m")
        print_problems()
        return
    try:
        mp_fields = {}
        if('csrftoken' in session.cookies): 
            mp_fields['csrfmiddlewaretoken'] = session.cookies['csrftoken']
        mp_fields = {
            **mp_fields, 
            'problem_instance_id' : problem_ids[task_name],
            'file' : (task_name + '.cpp', open(filename, 'rb'), 'text/x-c++src'),
        }
        mp_encoder = MultipartEncoder(
            mp_fields
        )
        head = SIO_headers
        head = { **head, 'Content-Type': mp_encoder.content_type}

        a = None
        task_url = server_url + 'c/' + contest_name + '/submit/'
        if(token):
            task_url = server_url + 'api/c/' + contest_name + '/submit/' 
            a = auth
        
        global r3
        r3 = None
        while(r3 == None  or r3.status_code != 200):
            #print("Cookies : ")
            #print(session.cookies.get_dict())
            #print("Result : ")
            #print(r.text)
            #print("My headers : ")
            #print(r.request.headers)
            #print("Multiform data:")
            #print(mp_fields)
            print("Submitting code...")
            r3 = session.post(
                task_url,
                data=mp_encoder,
                headers=head,
                auth=a,
                verify=False
            )
            
            if(r3 == None or r3.status_code != 200):
                print("Request failed, retrying in 10 seconds...")
                time.sleep(10)
        
        if(DUMP_RESPONSE):
                snap = open('dump_sub.html', 'w')
                snap.write(r3.text)
                snap.close()
        if(r3.url != task_url and r3.status_code == 200):
            try:
                subm_c = '/s/' + str(r3.json())
            except ValueError:
                subm_c = "/submissions"
            result_url = server_url + 'c/' + contest_name + subm_c
            
            print("\033[32;1mSubmission was received!\033[0m " + ("Submission code :\033[33;1m " + str(subm_c[3:]) if subm_c != '/submissions' else '') + "\033[0m View your status at : " + result_url)
            if open_webbrowser:
                    webbrowser.open_new_tab(result_url)
        elif(r3.status_code == 404):
            print("404 not found - maybe problem code is wrong?")
            print("\033[31;1mSubmission failed.\033[0m")
        else:
            print("\033[31mSomething went wrong.\033[0m Check \033[37;1m./dump.html\033[0m for more details.")
            print("Rsponse code : " + str(r3.status_code))
            snap = open('dump_sub.html', 'w')
            snap.write(r3.text)
            snap.close()

            #if('detail' in r.json()):
            #    print("Details : " + r.json()['detail'])
            #print(r.text)
            print("\033[31;1mSubmission failed.\033[0m")
    except Exception as e:
        print("Error:", e, file=sys.stderr)
        #print(e.with_traceback())
        print("\033[31;1mSubmission failed.\033[0m", file=sys.stderr)
        return 1

def get_problem_dict(server_url, contest_name):
    try:
        head = SIO_headers
        prob_url = server_url + 'c/' + contest_name + '/p/'
        
        global r_g
        r3 = None
        while(r3 == None  or r3.status_code != 200):

            print("Fetching problem list...")
            r3 = session.get(
                prob_url,
                headers=head,
                verify=False
            )
            
            if(r3 == None or r3.status_code != 200):
                print("Request failed, retrying in 10 seconds...")
                time.sleep(10)
        if(DUMP_RESPONSE):
            snap = open('dump_dict.html', 'w')
            snap.write(r.text)
            snap.close()
    except Exception as e:
        print("Error:", e, file=sys.stderr)
        print("Traceback:", e.with_traceback(), file=sys.stderr)
        #print(e.with_traceback())
        print("\033[31;1mSubmission failed - couldn't get problem list.\033[0m", file=sys.stderr)
        return 1
    soup = BeautifulSoup(r3.content, 'html.parser')
    tab = soup.find_all("div", class_="table-responsive")
    tab = tab[0]
    global tasks
    tasks = tab.find_all("tr", class_ = '')
    #Bez pierwszego tytułu
    tasks = tasks[1:]
    global problem_ids
    problem_ids = {}
    global problem_names
    problem_names = {}
    for t in tasks:
        problem_ids = { **problem_ids, t.td.text : t.div.attrs['id'][7:]}
        problem_names = { **problem_names, t.td.text : t.find_all('a')[0].text}


def get_id(server_url, contest_name, token=None):
    try:
        head = SIO_headers
        sol_url = server_url + 'c/' + contest_name + '/submissions/'
        
        global ri
        ri = None
        while(ri == None  or ri.status_code != 200):

            print("Getting problem id...")
            ri = session.get(
                sol_url,
                headers=head,
                verify=False
            )
            
            if(ri == None or ri.status_code != 200):
                print("Request failed, retrying in 10 seconds...")
                time.sleep(10)
        if(DUMP_RESPONSE):
            snap = open('dump_sol.html', 'w')
            snap.write(ri.text)
            snap.close()
    except Exception as e:
        print("Error:", e, file=sys.stderr)
        print("Traceback:", e.with_traceback(), file=sys.stderr)
        #print(e.with_traceback())
        print("\033[31;1mSubmission failed - couldn't get problem list.\033[0m", file=sys.stderr)
        return 1
    global soup
    soup = BeautifulSoup(ri.content, 'html.parser')
    global tab
    tab = soup.find_all('table', class_ = 'submission')
    tasks = tab.find_all("tr", class_ = '')
    print(tab)
    # global tasks
    # tasks = tab.find_all("tr", class_ = '')
    # #Bez pierwszego tytułu
    # tasks = tasks[1:]
    # dict = {}
    # for t in tasks:
    #     dict = { **dict, t.td.text : t.div.attrs['id'][7:]}
    # global problem_ids
    # problem_ids = dict

def print_problems():
    print('\033[37;1mValid problem codes are:\033[0m')
    for i in problem_ids:
        print( ' -> ' + problem_names[i] + " : '" + i + "'")
    
if __name__ == '__main__':
    sys.exit(main())



#print( mp_encoder.read().decode('utf-8') )

#head = SIO_headers | {'Content-Type': mp_encoder.content_type}

# print(head)



# print(r.text)
# #print(r.headers)
# print()
# #print(r.content)
# print(r.cookies)
# #print()
# print(r.json)

# print("\n")


