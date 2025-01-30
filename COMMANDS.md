# About The Commands

## Local Commands
These commands work without any interaction with the Repository.

### `rep_subject_credentials <password> <credentials file>`
This command does not interact with the Repository and creates a key pair for a subject, storing it in a credentials file.

### `rep_decrypt_file <encrypted file> <encryption metadata>`
This command sends to the stdout the contents of an encrypted file upon decryption (and integrity control) with the encryption metadata, that must contain the algorithms used to encrypt its contents and the encryption key.

## Commands that use the Anonymous API

### `rep_create_org <organization> <username> <name> <email> <public key file>`
This command creates an organization in a Repository and defines its first subject.

### `rep_list_orgs`
This command lists all organizations defined in a Repository.

### `rep_create_session <organization> <username> <password> <credentials file> <session file>`
This command creates a session for a username belonging to an organization, and stores the session context in a file.

### `rep_get_file <file handle> [file]`
This command downloads a file given its handle. The file contents are written to stdout or to the file referred in the optional last argument.

## Commands that use the Authenticated API
All these commands use as the first parameter a file with the session key.

### `rep_assume_role <session file> <role>`
This command requests the given role for the session.

### `rep_drop_role <session file> <role>`
This command releases the given role for the session.

### `rep_list_roles <session file> <role>`
This command lists the current session roles.

### `rep_list_subjects <session file> [username]`
This command lists the subjects of the organization with which I have currently a session.

### `rep_list_role_subjects <session file> <role>`
This command lists the subjects of a role of the organization with which I have currently a session.

### `rep_list_subject_roles <session file> <username>`
This command lists the roles of a subject of the organization with which I have currently a session.

### `rep_list_role_permissions <session file> <role>`
This command lists the permissions of a role of the organization with which I have currently a session.

### `rep_list_permission_roles <session file> <permission>`
This command lists the roles of the organization with which I have currently a session that have a given permission. Use the names previously referred for the permission rights.

### `rep_list_docs <session file> [-s username] [-d nt/ot/et date]`
This command lists the documents of the organization with which I have currently a session, possibly filtered by a subject that created them and by a date (newer than, older than, equal to), expressed in the DD-MM-YYYY format.

## Commands that use the Authorized API
All these commands use as the first parameter a file with the session key. For that session, the subject must have added one or more roles.

### `rep_add_subject <session file> <username> <name> <email> <credentials file>`
This command adds a new subject to the organization with which I have currently a session. By default, the subject is created in the active status. This command requires a SUBJECT_NEW permission.

### `rep_suspend_subject <session file> <username>`
### `rep_activate_subject <session file> <username>`
These commands change the status of a subject in the organization with which I have currently a session. These commands require a SUBJECT_DOWN and SUBJECT_UP permission, respectively.

### `rep_add_role <session file> <role>`
This command adds a role to the organization with which I have currently a session. This command requires a ROLE_NEW permission.

### `rep_suspend_role <session file> <role>`
### `rep_reactivate_role <session file> <role>`
These commands change the status of a role in the organization with which I have currently a session. These commands require a ROLE_DOWN and ROLE_UP permission, respectively.

### `rep_add_permission <session file> <role> <username>`
### `rep_remove_permission <session file> <role> <username>`
### `rep_add_permission <session file> <role> <permission>`
### `rep_remove_permission <session file> <role> <permission>`
These commands change the properties of a role in the organization with which I have currently a session, by adding a subject, removing a subject, adding a permission, or removing a permission, respectively. Use the names previously referred for the permission rights. These commands require a ROLE_MOD permission.

### `rep_add_doc <session file> <document name> <file>`
This command adds a document with a given name to the organization with which I have currently a session. The document’s contents are provided as a parameter with a file name. This command requires a DOC_NEW permission.

### `rep_get_doc_metadata <session file> <document name>`
This command fetches the metadata of a document with a given name to the organization with which I have currently a session. The output of this command is useful for getting the clear text contents of a document’s file. This command requires a DOC_READ permission.

### `rep_get_doc_file <session file> <document name> [file]`
This command is a combination of `rep_get_doc_metadata` with `rep_get_file` and `rep_decrypt_file`. The file contents are written to stdout or to the file referred in the optional last argument. This command requires a DOC_READ permission.

### `rep_delete_doc <session file> <document name>`
This command clears `file_handle` in the metadata of a document with a given name on the organization with which I have currently a session. The output of this command is the `file_handle` that ceased to exist in the document’s metadata. This command requires a DOC_DELETE permission.

### `rep_acl_doc <session file> <document name> [+/-] <role> <permission>`
This command changes the ACL of a document by adding (+) or removing (-) a permission for a given role. Use the names previously referred for the permission rights. This command requires a DOC_ACL permission.