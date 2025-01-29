import os
import sys
import argparse
import logging
import json
from metodos.metodos import *

logging.basicConfig(format='%(levelname)s\t- %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def load_state():
    state = {}
    state_dir = os.path.join(os.path.expanduser('~'), '.sio')
    state_file = os.path.join(state_dir, 'state.json')

    logger.debug('State folder: ' + state_dir)
    logger.debug('State file: ' + state_file)

    if os.path.exists(state_file):
        logger.debug('Loading state')
        with open(state_file,'r') as f:
            state = json.loads(f.read())

    if state is None:
        state = {}

    return state

def parse_env(state):
    if 'REP_ADDRESS' in os.environ:
        state['REP_ADDRESS'] = os.getenv('REP_ADDRESS')
        logger.debug('Setting REP_ADDRESS from Environment to: ' + state['REP_ADDRESS'])

    if 'REP_PUB_KEY' in os.environ:
        rep_pub_key = os.getenv('REP_PUB_KEY')
        logger.debug('Loading REP_PUB_KEY from: ' + rep_pub_key)
        if os.path.exists(rep_pub_key):
            with open(rep_pub_key, 'r') as f:
                state['REP_PUB_KEY'] = f.read()
                logger.debug('Loaded REP_PUB_KEY from Environment')
    return state

def parse_args(state):
    parser = argparse.ArgumentParser()
    parser.add_argument("-k", '--key', nargs=1, help="Path to the key file")
    parser.add_argument("-r", '--repo', nargs=1, help="Address:Port of the repository")
    parser.add_argument("-v", '--verbose', help="Increase verbosity", action="store_true")
    parser.add_argument("-c", "--command", help="Command to execute")
    parser.add_argument("-s", "--subject", help="Filter by subject (username)")
    parser.add_argument("-d", "--date", help="Filter by date (nt/ot/et DD-MM-YYYY)")
    parser.add_argument('arg0', nargs='?', default=None)
    parser.add_argument('arg1', nargs='?', default=None)
    parser.add_argument('arg2', nargs='?', default=None)
    parser.add_argument('arg3', nargs='?', default=None)
    parser.add_argument('arg4', nargs='?', default=None)
    parser.add_argument('arg5', nargs='?', default=None)

    args = parser.parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.info('Setting log level to DEBUG')

    if args.key:
        if not os.path.exists(args.key[0]) or not os.path.isfile(args.key[0]):
            logger.error(f'Key file not found or invalid: {args.key[0]}')
            sys.exit(-1)

        with open(args.key[0], 'r') as f:
            state['REP_PUB_KEY'] = f.read()
            logger.info('Overriding REP_PUB_KEY from command line')

    if args.repo:
        state['REP_ADDRESS'] = args.repo[0]
        logger.info('Overriding REP_ADDRESS from command line')
    
    if args.command:
        logger.info("Command: " + args.command)
       
    return state, {'command': args.command, 'subject': args.subject, 'date': args.date, 'arg0': args.arg0, 'arg1': args.arg1, 'arg2': args.arg2, 'arg3': args.arg3, 'arg4': args.arg4, 'arg5': args.arg5}

def save(state):
    state_dir = os.path.join(os.path.expanduser('~'), '.sio')
    state_file = os.path.join(state_dir, 'state.json')

    if not os.path.exists(state_dir):
      logger.debug('Creating state folder')
      os.mkdir(state_dir)

    with open(state_file, 'w') as f:
        f.write(json.dumps(state, indent=4))

state = load_state()
state = parse_env(state)
state, args = parse_args(state)

if 'REP_ADDRESS' not in state:
  logger.error("Must define Repository Address")
  sys.exit(-1)

if 'REP_PUB_KEY' not in state:
  logger.error("Must set the Repository Public Key")
  sys.exit(-1)
  
logger.debug("Arguments: " + str(args))

print("Program: ", args["command"])

# DONE
if args["command"] == "rep_subject_credentials":
    if None in [args["arg0"], args["arg1"]]:
        logger.error("Uso: rep_subject_credentials <password> <credentials file>")
        print("Uso: rep_subject_credentials <password> <credentials file>")
        sys.exit(1)
    password = args["arg0"]
    credentials_file = args["arg1"]
    rep_subject_credentials(password=password, credentials_file=credentials_file)

# DONE
elif args["command"] == "rep_decrypt_file":
    if None in [args["arg0"], args["arg1"]]:
        logger.error("Uso: rep_decrypt_file <encrypted file> <encryption metadata>")
        print("Uso: rep_decrypt_file <encrypted file> <encryption metadata>")
        sys.exit(1)
    rep_decrypt_file(args["arg0"], args["arg1"])

#DONE
elif args["command"]  == "rep_create_org":
    if None in [args["arg0"], args["arg1"], args["arg2"], args["arg3"], args["arg4"]]:
        logger.error("Uso: rep_create_org <organization> <username> <name> <email> <public key file>")
        print("Uso: rep_create_org <organization> <username> <name> <email> <public key file>")
        sys.exit(1)
    rep_create_org(state, args["arg0"], args["arg1"], args["arg2"], args["arg3"], args["arg4"])

elif args["command"] == "rep_list_orgs":
    rep_list_orgs(state)

#DONE
elif args["command"] == "rep_create_session":
    organization = args["arg0"]
    username = args["arg1"]
    password = args["arg2"]
    credentials_file = args["arg3"]
    session_file = args["arg4"]
    rep_create_session(state=state,
                       organization=organization,
                       username=username,
                       password=password,
                       credentials_file=credentials_file,
                       session_file=session_file)

#DONE
elif args["command"] == "rep_get_file":
    rep_get_file(state,args["arg0"], args["arg1"])

#DONE
elif args["command"] == "rep_list_subjects":
    rep_list_subjects(state, args["arg0"], args["arg1"])

#DONE
elif args["command"] == "rep_add_subject":
    session_file = args["arg0"]
    username = args["arg1"]
    name = args["arg2"]
    email = args["arg3"]
    credentials_file = args["arg4"]
    rep_add_subject(state=state,
                       session_file=session_file,
                       username=username,
                       name=name,
                       email=email,
                       credentials_file=credentials_file)
    
#DONE
elif args["command"] == "rep_suspend_subject":
    rep_suspend_subject(state, args["arg0"], args["arg1"])

#DONE
elif args["command"] == "rep_activate_subject":
    rep_activate_subject(state, args["arg0"], args["arg1"])

#DONE
elif args["command"] == "rep_add_role":
    rep_add_role(state, args["arg0"], args["arg1"])

#DONE
elif args["command"] == "rep_suspend_role":
    rep_suspend_role(state, args["arg0"], args["arg1"])

#DONE
elif args["command"] == "rep_reactivate_role":
    rep_reactivate_role(state, args["arg0"], args["arg1"])

#DONE
elif args["command"] == "rep_add_doc":
    rep_add_doc(state, args["arg0"], args["arg1"], args["arg2"])

#DONE
elif args["command"] == "rep_get_doc_metadata":
    rep_get_doc_metadata(state, args["arg0"], args["arg1"])

#DONE
elif args["command"] == "rep_get_doc_file":
    rep_get_doc_file(state, args["arg0"], args["arg1"], args["arg2"])

#DONE
elif args["command"] == "rep_delete_doc":
    rep_delete_doc(state, args["arg0"], args["arg1"])

#DONE
elif args["command"] == "rep_acl_doc":
    rep_acl_doc(state, args["arg0"], args["arg1"], args["arg2"], args["arg3"], args["arg4"])

#DONE
elif args["command"] == "rep_add_permission":
    if args["arg2"]:
        if args["arg2"].isupper():
            rep_add_permission_to_role(state, args["arg0"], args["arg1"], args["arg2"])
        else:
            rep_add_subject_to_role(state, args["arg0"], args["arg1"], args["arg2"])
    else:
        print("Erro: Argumentos insuficientes.")
        sys.exit(1)

#DONE
elif args["command"] == "rep_remove_permission":
    if args["arg2"]:
        if args["arg2"].isupper():
            rep_remove_permission_from_role(state, args["arg0"], args["arg1"], args["arg2"])
        else:
            rep_remove_subject_from_role(state, args["arg0"], args["arg1"], args["arg2"])
    else:
        print("Erro: Argumentos insuficientes para o comando.")
        sys.exit(1)

#DONE
elif args["command"] == "rep_list_docs":
    filters = {}

    if args["subject"]:
        filters["username"] = args["subject"]

    if args["date"]:
        date_parts = args["date"].split(" ", 1)
        if len(date_parts) == 2:
            filters["date"] = date_parts[1]
            filters["operator"] = date_parts[0].lower()
        else:
            logger.error("Invalid date filter format. Use nt/ot/et followed by a date in DD-MM-YYYY.")
            sys.exit(-1)
    
    rep_list_docs(state, args["arg0"], filters)

#DONE
elif args["command"] == "rep_assume_role":
    rep_assume_role(state, args["arg0"], args["arg1"])

#DONE
elif args["command"] == "rep_drop_role":
    rep_drop_role(state, args["arg0"], args["arg1"])

#DONE
elif args["command"] == "rep_list_roles":
    rep_list_roles(state, args["arg0"])

#DONE
elif args["command"] == "rep_list_role_subjects":
    rep_list_role_subjects(state, args["arg0"], args["arg1"])

#DONE
elif args["command"] == "rep_list_subject_roles":
    rep_list_subject_roles(state, args["arg0"], args["arg1"])

#DONE
elif args["command"] == "rep_list_role_permissions":
    rep_list_role_permissions(state, args["arg0"], args["arg1"])

elif args["command"] == "rep_list_permission_roles":
    rep_list_permission_roles(state, args["arg0"], args["arg1"])

else:
  logger.error("Invalid command")

