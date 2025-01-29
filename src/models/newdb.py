from sqlalchemy import create_engine, Column, String, JSON
from sqlalchemy.dialects.postgresql import BYTEA
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()

# Tabela de Organizações
class Organization(Base):
    __tablename__ = "organizations"
    name = Column(String, primary_key=True)
    data = Column(JSON, nullable=False)

# Tabela de Sessões
class Session(Base):
    __tablename__ = "sessions"
    session_id = Column(String, primary_key=True)
    data = Column(JSON, nullable=False)

# Tabela de Arquivos
class File(Base):
    __tablename__ = "files"
    file_handle = Column(String, primary_key=True)
    data = Column(String, nullable=False)

# Tabela de Documentos
class Document(Base):
    __tablename__ = "documents"
    document_handle = Column(String, primary_key=True)
    data = Column(JSON, nullable=False)

# Inicializar banco de dados
DATABASE_URL = "postgresql://myuser:mypassword@localhost:5432/mydatabase"
engine = create_engine(DATABASE_URL, echo=True)
Base.metadata.create_all(engine)
SessionLocal = sessionmaker(bind=engine)
