from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Enum, TIMESTAMP, TIME
from sqlalchemy.dialects.postgresql import ARRAY, JSON
from sqlalchemy.orm.attributes import flag_modified
from datetime import datetime
import uuid
import enum
import json

Base = declarative_base()

class Status(enum.Enum):
    ACTIVE = "active"
    SUSPEND = "suspend"

class ACL(enum.Enum):
    DOC_ACL = "doc_acl"
    DOC_READ = "doc_read"
    DOC_DELETE = "doc_delete"
    ROLE_ACL = "doc_acl"
    SUBJECT_NEW = "subject_new"
    SUBJECT_DOWN = "subject_down"
    SUBJECT_UP = "subject_u+"
    DOC_NEW = "doc_new"
    ROLE_NEW = "role_new"
    ROLE_DOWN = "role_down"
    ROLE_UP = "role_up"
    ROLE_MOD = "role_mod"

class Subject(Base):
    __tablename__ = "subjects"

    username = Column(String, primary_key=True)
    full_name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    public_key = Column(String, nullable=False)

class Role(Base):
    __tablename__ = 'roles'

    id = Column(String, primary_key=True, default=str(uuid.uuid4))
    name = Column(String, nullable=False)
    permission = Column(ARRAY(Enum(ACL)), default=[], nullable=False)
    subjects = Column(ARRAY(String), default=[] , nullable=False)

class Document(Base):
    __tablename__ = "documents"
    # public metadata
    document_handle = Column(String, primary_key=True, default=str(uuid.uuid4))
    name = Column(String, nullable=False)
    create_date = Column(TIME, nullable=False)
    creator = Column(String, ForeignKey("subjects.username"), nullable=False)
    file_handle = Column(String)
    acl = Column(ARRAY(String), default=[], nullable=False) # role list, at least one role must keep DOC_ACL
    deleter = Column(String, ForeignKey("subjects.username"))

    # restrict metadata 
    alg = Column(String, nullable=False)
    key = Column(String, nullable=False)
    key_iv = Column(String, nullable=False)

    def del_file(self):
        file = self.file_handle
        self.file_handle = None
        return file

class Organization(Base):
    __tablename__ = "organizations"  
    
    organization = Column(String, primary_key=True)
    subjects = Column(JSON, default={}, nullable=False)
    documents = Column(ARRAY(String), default=[], nullable=False) # doc handle
    roles = Column(ARRAY(String), default=[], nullable=False) # role id

    def add_subject(self, username):
        self.subjects[username] = Status.ACTIVE.value
        flag_modified(self, "subjects")

    def add_doc(self, doc_handle):
        self.documents.append(doc_handle)
        flag_modified(self, "documents")

    def change_status(self, username, status):
        if username in self.subjects:
            self.subjects[username] = status.value
            flag_modified(self, "subjects")

class Session(Base):
    __tablename__ = "sessions"

    session_id = Column(String, primary_key=True)
    subject = Column(String, ForeignKey("subjects.username"), nullable=False)
    organization = Column(String, ForeignKey("organizations.organization"), nullable=False)
    keys = Column(ARRAY(String), nullable=False) 

class DBManager():

    def __init__(self):
        DATABASE_URL = "postgresql://myuser:mypassword@localhost:5432/mydatabase"
        self.engine = create_engine(DATABASE_URL)
        # Base.metadata.drop_all(self.engine)
        Base.metadata.create_all(self.engine)

        session = sessionmaker(bind=self.engine)
        self.session = session()

    def addOrganization(self, organization, username, name, email, public_key):
        subject = Subject(username=username, full_name=name, email=email, public_key=public_key)
        self.session.add(subject)
        manager = Role(name="Maneger", 
                permission=[ACL.ROLE_ACL, ACL.SUBJECT_NEW, ACL.SUBJECT_DOWN, ACL.SUBJECT_UP, ACL.DOC_NEW, ACL.ROLE_NEW, ACL.ROLE_DOWN, ACL.ROLE_UP,ACL.ROLE_MOD],
                subjects=[subject.username])
        self.session.add(manager)
        org = Organization(organization=organization, roles=[manager.id], subjects={})
        org.add_subject(subject.username)
        self.session.add(org)

        self.session.commit()

    def listOrganization(self):
        return list(org.organization for org in self.session.query(Organization).all())       
    
    def getSessionById(self, session_id):
        for s in self.session.query(Session).all():
            if s.session_id == session_id:
                return s
    
    def getOrganization(self, organization) -> Organization:
        for org in self.session.query(Organization).filter(Organization.organization == organization).all():
            return org
            
    def getDocument(self, document_handle) -> Document:
        for doc in self.session.query(Document).filter(Document.document_handle == document_handle).all():
            return doc
            
    def getDocMetadata(self, session_id, doc_name):
        s = self.getSessionById(session_id)
        if s is None:
            return None
        org = self.getOrganization(s.organization)
        if org is None:
            return None
        
        for handle in org.documents:
            doc = self.getDocument(handle)
            if doc.name == doc_name:
                return {"document_handle":doc.document_handle,
                        "name":doc.name,
                        "create_date":doc.create_date,
                        "creator":doc.creator,
                        "file_handle":doc.file_handle,
                        "deleter":doc.deleter,}
            
    def addSubject(self, organization, username, name, email, public_key):
        subject = Subject(username=username, full_name=name, email=email, public_key=public_key)
        org = self.getOrganization(organization)
        org.add_subject(subject.username)
        self.session.add(subject)
        self.session.add(org)
        self.session.commit()
                
    def addSession(self, session_id, organization, username, public_key):
        s = Session(session_id=session_id, subject=username, organization=organization, keys=[public_key])
        self.session.add(s)
        self.session.commit()

    def addDocument(self, organization, doc_handle, doc_name, create_date, creator, file_handle, acl, alg, key, key_iv):
        doc = Document(document_handle=doc_handle, name=doc_name, create_date=create_date, creator=creator, file_handle=file_handle, acl=acl, alg=alg, key=key, key_iv=key_iv)
        org = self.getOrganization(organization)
        if org is None:
            return None
        org.add_doc(doc.document_handle)
        self.session.add(doc)
        self.session.add(org)
        self.session.commit()

    def removeDocument(self, organization, doc_name):
        org = self.getOrganization(organization)
        if org is None:
            return None
        for handle in org.documents:
            doc = self.getDocument(handle)
            if doc.name == doc_name and doc.file_handle != None:
                return doc.del_file()

    def listSubjects(self, organization, username=None):
        org = self.getOrganization(organization)
        if org is None:
            return None
        return list((sub,org.subjects[sub]) for sub in org.subjects if username is None or sub==username)
    
    def listDocuments(self, organization, username=None, op=None, date=None):
        org = self.getOrganization(organization)
        if org is None:
            return None
        lst = []
        for doc_handle in org.documents:
            doc = self.getDocument(doc_handle)
            if not (username is None or username == doc.creator):
                continue
            if (op is not None and date is not None):
                if (op == "nt" and doc.create_date > date):
                    lst.append(doc.name)
                elif (op == "ot" and doc.create_date < date):
                    lst.append(doc.name)
                elif (op == "et" and doc.create_date == date):
                    lst.append(doc.name)
            else:
                lst.append(doc.name)
        return lst
    
    # Não pode suspender um manager se for o único
    def suspendSubject(self, organization, username):
        org = self.getOrganization(organization)
        org.change_status(username, Status.SUSPEND)
        self.session.add(org)
        self.session.commit()

    def activeSubject(self, organization, username):
        org = self.getOrganization(organization)
        org.change_status(username, Status.ACTIVE)
        self.session.add(org)
        self.session.commit()


if __name__ == "__main__":
    db = DBManager()
    
    # db.addOrganization("org1","user1","giovanni santos","a@a.a","bbss")
    # db.addSubject("org1", "user2", "sheshe", "she@she.she", "ccvv")
    # db.addSubject("org1", "user3", "she she", "she@sh.sh", "ccv12v")
    print(db.listSubjects("org1"))
    # db.suspendSubject("org1","user2")
    print(db.listSubjects("org1"))

    # db.addDocument(
    #     organization="org1",
    #     doc_handle="doc-001",
    #     doc_name="Relatório Financeiro Anual",
    #     create_date=datetime(2024, 1, 15, 10, 30),
    #     creator="user1",  
    #     file_handle="file-handle-001",
    #     alg="AES256",
    #     key="random-key-123"
    # )

    # db.addDocument(
    #     organization="org1",
    #     doc_handle="doc-002",
    #     doc_name="Plano de Projeto 2024",
    #     create_date=datetime(2024, 3, 20, 14, 45),
    #     creator="user2",
    #     file_handle="file-handle-002",
    #     alg="RSA1024",
    #     key="secure-key-456"
    # )

    # db.addDocument(
    #     organization="org1",
    #     doc_handle="doc-003",
    #     doc_name="Atas da Reunião de Diretoria",
    #     create_date=datetime(2024, 5, 10, 9, 0),
    #     creator="user3",
    #     file_handle="file-handle-003",
    #     alg="ChaCha20",
    #     key="special-key-789"
    # )

    # print(db.listDocuments("org1"))