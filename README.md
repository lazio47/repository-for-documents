# Secure Document Repository
*Shelton Lázio Agostinho - 2024*

## Overview
The Secure Document Repository is a system that enables organizations to securely store, manage, and share documents among authorized members. The repository ensures encryption for file storage, controlled access through ACLs, and structured roles for managing permissions.

## Features
- **Secure document storage**: Documents are encrypted before storage.
- **Access Control Lists (ACLs)**: Defines who can read, modify, and delete documents.
- **Organizational structure**: Documents belong to organizations with controlled access.
- **Role-based access**: Subjects are assigned roles that define their permissions.
- **Session-based authentication**: Users interact with the system via secured sessions.
- **Secure key management**: Encryption keys are securely managed within the repository.
- **Comprehensive API**: Provides endpoints for managing users, roles, documents, and permissions.

## High-Level Functionalities

### Documents and Files
Each document consists of:
1. **Public Metadata** (stored in plaintext):
   - `document_handle`: Unique identifier for the document.
   - `name`: Name of the document.
   - `create_date`: Creation timestamp.
   - `creator`: Subject who created the document.
   - `file_handle`: Handle to locate the file.
   - `acl`: Access Control List.
   - `deleter`: Reference to the subject who deleted the file.
2. **Restricted Metadata**:
   - `alg`: Encryption algorithm used.
   - `key`: Encrypted key for document decryption.

### Access Control List (ACL) Permissions
Each document ACL defines access rights:
- `DOC_ACL`: Modify the document's ACL.
- `DOC_READ`: Read the file content.
- `DOC_DELETE`: Mark a document as deleted.

### Organizations
Organizations group documents and users. Each organization has:
- A `Managers` role with full control.
- Permissions such as `ROLE_ACL`, `SUBJECT_NEW`, `DOC_NEW`, etc.

### Subjects (Users)
Subjects are individuals or applications interacting with the repository. Each subject has:
- A `username`, `full_name`, `email`, and `public_key`.

### Sessions
- Secure interactions are session-based.
- Each session has an identifier and session keys for security.
- Sessions are resistant to eavesdropping, impersonation, manipulation, and replay attacks.

### Roles
- Subjects are assigned roles that grant permissions.
- Roles are used in ACLs instead of direct subject references.
- The `Managers` role must always have at least one active subject.

## Fundamental Operations

### Uploading a Document
1. User logs in and assumes a role with `DOC_NEW` permission.
2. The file is encrypted with a randomly generated key.
3. The file and metadata are uploaded to the repository.

### Downloading a Document
1. User logs in and assumes a role with `DOC_READ` permission.
2. The metadata (including encryption details) is retrieved.
3. The encrypted file is fetched and decrypted.

### Deleting a Document
1. User logs in and assumes a role with `DOC_DELETE` permission.
2. The document metadata is updated to clear the file handle.
3. The file remains accessible to users who possess its file handle and decryption key.

## API Endpoints

### Anonymous API
- `POST /organization/create` - Create an organization.
- `GET /organization/list` - List organizations.
- `POST /session/create` - Create a user session.
- `POST /file/download` - Download a file using its handle.

### Authenticated API
- `POST /role/assume` - Assume a session role.
- `POST /role/drop` - Release a session role.
- `POST /role/list` - List available roles.
- `POST /subject/list` - List subjects in the organization.
- `POST /role/subjects` - List subjects assigned to a role.
- `POST /subject/roles` - List roles assigned to a subject.
- `POST /role/permissions` - List permissions assigned to a role.
- `POST /role/permission_roles` - List roles that have a given permission.
- `POST /documents/list` - List organization documents with filters.

### Authorized API (Requires Role Permissions)
- `POST /subject/add` - Add a subject to an organization.
- `POST /subject/status` - Change a subject's status (activate/suspend).
- `POST /role/add` - Add a role to an organization.
- `POST /role/status` - Change a role's status.
- `POST /role/modify` - Modify a role (add/remove subjects or permissions).
- `POST /document/add` - Upload a new document.
- `POST /document/metadata` - Retrieve document metadata.
- `POST /document/delete` - Mark a document as deleted.
- `POST /document/acl` - Modify a document's ACL.

## Security Guidelines
- The repository uses a well-known public key for securing anonymous API calls.
- Session keys are used for encryption, integrity control, and authentication.
- A master key is used to protect document encryption keys.
- Communication security implemented internally without using SSL/TLS.

## Implementation Guidelines
- Clients interact with the repository using command-line applications.
- Each command should store its state to allow subsequent operations.
- Commands follow UNIX semantics.

## Setup and Running the Server
### Prerequisites
- Python 3.x
- Flask
- SQLAlchemy

### Installation
```bash
# Clone the repository
git clone https://github.com/lazio47/repository-for-documents.git
cd repository-for-documents

# Criate a virtual environment
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set address and location of the repository public key
cd src
export REP_ADDRESS="127.0.0.1:5000" # or other
export REP_PUB_KEY="./repo_public_key.pem"

# Start the database and the tables
docker compose up -d

# In other terminal, on /src, activate the virtual environment and start the repository
python3 api/repository.py
```

### Running Client Commands
To interact with the repository, use the provided command-line tools. Example:
```bash
# In the first terminal exectute any command, [see more on COMMANDS.md]
./rep_create_org myorg username "Full Name" email@example.com credentials.json

# Or try the tests
./tests.sh
```

### For the permissions
```bash
# For the test file
chmod u+x tests.sh
# For the commands
chmod +x rep_*
```

## About the commands
More about the commands in [COMMANDS.md](COMMANDS.md).

## License
I developed this project on a SIO subject on Universidade de Aveiro.

## Future Improvements
- Implement UI for easier management.
- Introduce additional encryption mechanisms.
- Extend support for more granular permissions.