from app.extensions import db
from sqlalchemy import CheckConstraint

class FileType(db.Model):
    __tablename__ = 'FileType'

    ID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Type = db.Column(db.String(255), nullable=False)

    # Define the reverse relationship to Signature
    signatures = db.relationship("Signature", back_populates="file_type")
    
    def __init__(self, Type):
        self.Type = Type

    def __repr__(self):
        return f"<FileType ID={self.ID} Type={self.Type}>"
    
class Source(db.Model):
    __tablename__ = 'Source'  # Table name in the database

    ID = db.Column(db.Integer, primary_key=True, autoincrement=True)  # Primary key (auto-incremented)
    Name = db.Column(db.String(255), nullable=False)  # Source name (required field)

    # Define the reverse relationship to Signature
    signatures = db.relationship("Signature", back_populates="source")

    def __init__(self, Name):
        self.Name = Name

    def __repr__(self):
        return f"<Source(ID={self.ID}, Name={self.Name})>"
    
class SpywareCategory(db.Model):
    __tablename__ = 'SpywareCategory'

    ID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Category = db.Column(db.String(255), nullable=False)

    # Reverse relationship with SpywareName
    spyware_names = db.relationship('SpywareName', back_populates='spyware_category')

    def __init__(self, Category):
        self.Category = Category

    def __repr__(self):
        return f"<SpywareCategory(ID={self.ID}, Category={self.Category})>"

class SpywareName(db.Model):
    __tablename__ = 'SpywareName'

    ID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Name = db.Column(db.String(255), nullable=False)
    SpywareCategoryID = db.Column(db.Integer, db.ForeignKey('SpywareCategory.ID'), nullable=False)

    # Relationship with SpywareCategory
    spyware_category = db.relationship('SpywareCategory', back_populates='spyware_names')
    
    # Define the reverse relationship for signatures explicitly
    signatures = db.relationship('Signature', back_populates='spyware_name')


    def __init__(self, Name, SpywareCategoryID):
        self.Name = Name
        self.SpywareCategoryID = SpywareCategoryID

    def __repr__(self):
        return f"<SpywareName(ID={self.ID}, Name={self.Name}, SpywareCategoryID={self.SpywareCategoryID})>"
  
class Signature(db.Model):
    __tablename__ = 'Signature'

    ID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Signature = db.Column(db.String(255), nullable=False)
    EntryStatus = db.Column(db.Integer, nullable=False)
    InsertDate = db.Column(db.DateTime, nullable=False, default=db.func.now())  # Runtime default
    UpdateDate = db.Column(db.DateTime, nullable=False, default=db.func.now(), onupdate=db.func.now())  # Runtime default and update
    SpywareNameID = db.Column(db.Integer, db.ForeignKey('SpywareName.ID'), nullable=False)
    HitsCount = db.Column(db.Integer, default=0)
    SourceID = db.Column(db.Integer, db.ForeignKey('Source.ID'), nullable=False)
    FileTypeID = db.Column(db.Integer, db.ForeignKey('FileType.ID'), nullable=False)

    spyware_name = db.relationship("SpywareName", back_populates="signatures")
    source = db.relationship("Source", back_populates="signatures")
    file_type = db.relationship("FileType", back_populates="signatures")
    white_file_names = db.relationship('WhiteFileName', back_populates='signature')
    hits = db.relationship('Hits', back_populates='signature')

    @property
    def SpywareInfo(self):
        """Concatenate Spyware Category and Spyware Name"""
        if self.spyware_name and self.spyware_name.category:
            return f"{self.spyware_name.category.Category} - {self.spyware_name.Name}"
        return None

    def __init__(self, Signature, EntryStatus, SpywareNameID, SourceID, FileTypeID, HitsCount=0):
        self.Signature = Signature
        self.EntryStatus = EntryStatus
        self.SpywareNameID = SpywareNameID
        self.SourceID = SourceID
        self.FileTypeID = FileTypeID
        self.HitsCount = HitsCount

    def __repr__(self):
        return f"<Signature(ID={self.ID}, Signature={self.Signature}, EntryStatus={self.EntryStatus})>"


class WhiteFileName(db.Model):
    __tablename__ = 'WhiteFileName'

    ID = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(255), nullable=False)
    SignatureTableID = db.Column(db.Integer, db.ForeignKey('Signature.ID', ondelete='CASCADE'), nullable=False)
    

    signature = db.relationship('Signature', back_populates='white_file_names')

    def __repr__(self):
        return f'<WhiteFileName {self.Name}>'
    
class Hits(db.Model):
    __tablename__ = 'Hits'
    
    ID = db.Column(db.Integer, primary_key=True)
    SignatureTableID = db.Column(db.Integer, db.ForeignKey('Signature.ID'), nullable=False)
    Hits = db.Column(db.Integer, nullable=False)

    # Define relationship to Signature (assuming Signature model is defined)
    signature = db.relationship('Signature', back_populates='hits')

# malicious url model started here
class MaliciousURLs(db.Model):
    __tablename__ = 'MaliciousURLs'
    ID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    URL = db.Column(db.Text, nullable=False)
    VendorID = db.Column(db.Integer, nullable=False)
    EntryStatus = db.Column(db.Integer, nullable=False, default=0)

    # Add CheckConstraint for EntryStatus
    __table_args__ = (
        CheckConstraint('EntryStatus IN (0, 1)', name='ck_entry_status_valid'),
    )

    